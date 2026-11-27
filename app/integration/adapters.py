import hmac
import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from app.domain.models import User
from app.enums import IncidentType, PdnFlag, Severity, SourceType
from app.repositories.sqlite_repo import UserRepository, hash_password


def _first_text(raw: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Return the first non-empty stripped string value found among candidate keys."""
    for key in keys:
        val = raw.get(key)
        if val is None:
            continue
        text = str(val).strip()
        if text:
            return text
    return ""


class SourceAdapter(ABC):
    """Abstract base adapter for external security signal sources."""

    @property
    @abstractmethod
    def source_type(self) -> SourceType:
        """Source identifier served by this adapter."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw source payload into canonical signal fields."""

    def poll(self) -> list[dict[str, Any]]:
        """Poll external source for new raw events (empty in push/emulator mode)."""
        return []

    def _normalize_fields(
        self,
        raw: dict[str, Any],
        *,
        default_type: IncidentType,
        sender_keys: tuple[str, ...],
        computer_keys: tuple[str, ...],
        employee_keys: tuple[str, ...],
        body_keys: tuple[str, ...],
        key_keys: tuple[str, ...],
        title_keys: tuple[str, ...] = ("title",),
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError("Signal payload must be a dictionary")

        raw_type = raw.get("incident_type")
        if raw_type is not None and str(raw_type).strip():
            incident_type = IncidentType.normalize(str(raw_type)).value
        else:
            incident_type = default_type.value

        raw_sev = raw.get("severity")
        if raw_sev is not None and str(raw_sev).strip():
            severity = Severity.normalize(raw_sev).value
        else:
            severity = Severity.MEDIUM.value

        pdn = PdnFlag.from_bool_int(raw.get("has_personal_data", 0)).to_bool_int()
        title_text = _first_text(raw, title_keys)

        return {
            "source": self.source_type.value,
            "sender": _first_text(raw, sender_keys),
            "body": _first_text(raw, body_keys),
            "computer": _first_text(raw, computer_keys),
            "employee": _first_text(raw, employee_keys),
            "incident_type": incident_type,
            "severity": severity,
            "incident_key": _first_text(raw, key_keys),
            "has_personal_data": pdn,
            "title": title_text or None,
        }


class KasperskyAdapter(SourceAdapter):
    """Adapter for Kaspersky Endpoint Security / antivirus alerts."""

    source_type: SourceType = SourceType.KASPERSKY

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize an antivirus alert payload."""
        return self._normalize_fields(
            raw,
            default_type=IncidentType.VIRUS,
            sender_keys=("sender", "agent", "ksc_server"),
            computer_keys=("computer", "host", "hostname", "device", "workstation"),
            employee_keys=("employee", "user", "username", "account"),
            body_keys=("body", "message", "threat", "malware", "description"),
            key_keys=("incident_key", "event_id", "alert_id"),
        )


class ZabbixAdapter(SourceAdapter):
    """Adapter for Zabbix infrastructure and availability triggers."""

    source_type: SourceType = SourceType.ZABBIX

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a Zabbix trigger payload."""
        return self._normalize_fields(
            raw,
            default_type=IncidentType.OTHER,
            sender_keys=("sender", "proxy", "server"),
            computer_keys=("computer", "host", "hostname"),
            employee_keys=("employee", "owner"),
            body_keys=("body", "trigger", "message", "alert", "description"),
            key_keys=("incident_key", "trigger_id", "event_id"),
        )


class MailAdapter(SourceAdapter):
    """Adapter for mail gateway / phishing email notifications."""

    source_type: SourceType = SourceType.EMAIL

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a mail gateway alert payload."""
        return self._normalize_fields(
            raw,
            default_type=IncidentType.PHISHING,
            sender_keys=("sender", "from", "from_addr"),
            computer_keys=("computer", "host", "hostname"),
            employee_keys=("employee", "recipient", "to"),
            body_keys=("body", "text", "message", "subject"),
            key_keys=("incident_key", "message_id"),
            title_keys=("title", "subject"),
        )


class TelegramAdapter(SourceAdapter):
    """Adapter for Telegram bot incident reports and Bot API outbound delivery."""

    source_type: SourceType = SourceType.TELEGRAM
    MAX_MESSAGE_LENGTH: int = 4000

    def __init__(
        self,
        bot_token: str | None = None,
        *,
        api_base: str = "https://api.telegram.org",
        timeout: float = 5.0,
        transport: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.sent_messages: list[dict[str, str]] = []
        self.bot_token: str = (bot_token or "").strip()
        self.api_base: str = api_base.rstrip("/")
        self.timeout: float = timeout
        self._transport = transport
        self.last_error: str | None = None

    def _resolve_token(self, bot_token: str | None = None) -> str:
        if bot_token is not None:
            return bot_token.strip()
        if self.bot_token:
            return self.bot_token
        return os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()

    def call_api(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        *,
        bot_token: str | None = None,
    ) -> dict[str, Any]:
        """Invoke a Telegram Bot API method via injectable transport or urllib."""
        body_dict = dict(payload or {})
        if self._transport is not None:
            try:
                res = self._transport(method, body_dict)
                self.last_error = None if res.get("ok") else str(res.get("description") or "Telegram API error")
                return res
            except Exception as exc:
                self.last_error = str(exc)
                return {"ok": False, "description": self.last_error}

        token = self._resolve_token(bot_token)
        if not token:
            self.last_error = "Telegram bot token is not configured"
            return {"ok": False, "description": self.last_error}

        url = f"{self.api_base}/bot{token}/{method}"
        data = json.dumps(body_dict, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_resp = resp.read().decode("utf-8")
            parsed = json.loads(raw_resp) if raw_resp else {"ok": False, "description": "Empty response"}
            if not isinstance(parsed, dict):
                self.last_error = "Invalid Telegram API response"
                return {"ok": False, "description": self.last_error}
            self.last_error = (
                None if parsed.get("ok") else str(parsed.get("description") or "Telegram API error")
            )
            return parsed
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
                parsed_err = json.loads(err_body)
                desc = str(parsed_err.get("description") or err_body)
            except Exception:
                desc = err_body or str(exc)
            self.last_error = f"HTTP {exc.code}: {desc}"
            return {"ok": False, "error_code": exc.code, "description": self.last_error}
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            self.last_error = str(exc)
            return {"ok": False, "description": self.last_error}

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize an incoming Telegram message payload."""
        return self._normalize_fields(
            raw,
            default_type=IncidentType.OTHER,
            sender_keys=("sender", "username", "from_user", "chat_id"),
            computer_keys=("computer", "host", "hostname"),
            employee_keys=("employee", "full_name", "username"),
            body_keys=("body", "text", "message"),
            key_keys=("incident_key", "update_id", "message_id"),
        )

    def send_message(
        self,
        user: str,
        text: str,
        *,
        bot_token: str | None = None,
        parse_mode: str | None = None,
    ) -> bool:
        """Deliver an outbound Telegram message via Bot API or in-memory fallback."""
        target = str(user).strip()
        body = str(text).strip()
        if not target or not body:
            return False
        if len(body) > self.MAX_MESSAGE_LENGTH:
            body = body[: self.MAX_MESSAGE_LENGTH - 3] + "..."

        token = self._resolve_token(bot_token)
        if not token and self._transport is None:
            self.last_error = None
            self.sent_messages.append({"user": target, "text": body})
            return True

        payload: dict[str, Any] = {
            "chat_id": target,
            "text": body,
            "disable_web_page_preview": True,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode

        res = self.call_api("sendMessage", payload, bot_token=token)
        if res.get("ok"):
            self.sent_messages.append({"user": target, "text": body})
            return True
        return False

    def get_me(self, *, bot_token: str | None = None) -> dict[str, Any]:
        """Fetch bot profile info via Telegram getMe."""
        return self.call_api("getMe", {}, bot_token=bot_token)

    def get_updates(
        self,
        *,
        offset: int | None = None,
        limit: int = 20,
        bot_token: str | None = None,
    ) -> dict[str, Any]:
        """Fetch recent incoming updates via Telegram getUpdates."""
        payload: dict[str, Any] = {"limit": limit, "timeout": 0}
        if offset is not None:
            payload["offset"] = offset
        return self.call_api("getUpdates", payload, bot_token=bot_token)

    def set_webhook(
        self,
        url: str,
        *,
        secret_token: str = "",
        bot_token: str | None = None,
    ) -> dict[str, Any]:
        """Configure Telegram Bot API webhook URL and optional secret header."""
        payload: dict[str, Any] = {"url": url.strip()}
        if secret_token.strip():
            payload["secret_token"] = secret_token.strip()
        return self.call_api("setWebhook", payload, bot_token=bot_token)

    def delete_webhook(self, *, bot_token: str | None = None) -> dict[str, Any]:
        """Remove configured Telegram webhook."""
        return self.call_api("deleteWebhook", {}, bot_token=bot_token)

    def reply_number(
        self,
        chat_id: str,
        incident_id: int,
        *,
        bot_token: str | None = None,
    ) -> bool:
        """Send an incident registration number confirmation to a Telegram chat."""
        if incident_id is None or int(incident_id) <= 0:
            return False
        return self.send_message(
            str(chat_id),
            f"Инцидент #{incident_id} зарегистрирован",
            bot_token=bot_token,
        )


ADAPTER_REGISTRY: dict[SourceType, SourceAdapter] = {
    SourceType.KASPERSKY: KasperskyAdapter(),
    SourceType.ZABBIX: ZabbixAdapter(),
    SourceType.EMAIL: MailAdapter(),
    SourceType.TELEGRAM: TelegramAdapter(),
}


class AuthProvider(ABC):
    """Abstract authentication provider returning an authenticated User or None."""

    @abstractmethod
    def authenticate(self, login: str, password: str) -> User | None:
        """Verify credentials and return the matching active User if valid."""


class LocalAuth(AuthProvider):
    """Local SQLite-backed SHA-256 credential authentication provider."""

    def __init__(self, user_repo: UserRepository) -> None:
        self.user_repo = user_repo

    def authenticate(self, login: str, password: str) -> User | None:
        """Authenticate against stored local user password hashes."""
        if not login:
            return None
        found = self.user_repo.find_with_password(login)
        if found is None:
            return None
        user, password_hash = found
        if not user.active:
            return None
        if hmac.compare_digest(password_hash, hash_password(password)):
            return user
        return None


class DomainAuth(AuthProvider):
    """Active Directory authentication provider with LocalAuth fallback."""

    def __init__(
        self,
        local_auth: LocalAuth | UserRepository,
        domain_available: bool = False,
        ad_verifier: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.local_auth = (
            local_auth if isinstance(local_auth, LocalAuth) else LocalAuth(local_auth)
        )
        self.domain_available = domain_available
        self.ad_verifier = ad_verifier

    def authenticate(self, login: str, password: str) -> User | None:
        """Authenticate via AD when available, falling back to LocalAuth otherwise."""
        if self.domain_available and self.ad_verifier is not None:
            try:
                if not self.ad_verifier(login, password):
                    return None
                user = self.local_auth.user_repo.get_by_username(login)
                return user if user is not None and user.active else None
            except (OSError, ConnectionError, TimeoutError, RuntimeError):
                return self.local_auth.authenticate(login, password)
        return self.local_auth.authenticate(login, password)
