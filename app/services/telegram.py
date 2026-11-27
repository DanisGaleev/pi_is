import html
import os
from collections.abc import Mapping
from typing import Any

from app.domain.models import Incident, TelegramSettings, TelegramSubscription, User
from app.enums import (
    Channel,
    DeliveryStatus,
    IncidentStatus,
    PdnFlag,
    Role,
    Severity,
)
from app.integration.adapters import TelegramAdapter
from app.repositories.sqlite_repo import (
    IncidentRepository,
    NotificationRepository,
    TelegramRepository,
    UserRepository,
    utc_now,
)
from app.services.access import AccessControlService
from app.services.exceptions import NotFoundError, ValidationError, coerce_user
from app.services.validators import require_non_blank

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 Критический",
    Severity.HIGH: "🟠 Высокий",
    Severity.MEDIUM: "🟡 Средний",
    Severity.LOW: "🟢 Низкий",
}

_STATUS_BADGE: dict[str, str] = {
    IncidentStatus.NEW.value: "🆕 Новый",
    IncidentStatus.IN_PROGRESS.value: "🛠 В работе",
    IncidentStatus.IN_REVIEW.value: "🔎 На проверке",
    IncidentStatus.CLOSED.value: "✅ Закрыт",
}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _truncate(text: str, limit: int = 320) -> str:
    cleaned = (text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def _severity_label(raw: str) -> str:
    try:
        sev = Severity.normalize(raw)
        return _SEVERITY_BADGE.get(sev, sev.label)
    except ValueError:
        return raw or "-"


def _status_label(raw: str) -> str:
    return _STATUS_BADGE.get(raw, raw or "-")


def _normalize_optional_role(raw: Any) -> str:
    if raw is None:
        return ""
    cleaned = str(raw).strip()
    if not cleaned:
        return ""
    try:
        return Role(cleaned).value
    except ValueError as exc:
        raise ValidationError(f"Неизвестная роль для подписки: {cleaned!r}") from exc


def _normalize_severity(raw: Any, default: Severity = Severity.LOW) -> str:
    if raw is None or not str(raw).strip():
        return default.value
    try:
        return Severity.normalize(str(raw)).value
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


class TelegramNotificationService:
    """Manage Telegram bot configuration, chat subscriptions, delivery, and commands."""

    def __init__(
        self,
        telegram_repo: TelegramRepository,
        notification_repo: NotificationRepository,
        incident_repo: IncidentRepository,
        user_repo: UserRepository,
        access_control: AccessControlService,
        telegram_adapter: TelegramAdapter | None = None,
    ) -> None:
        self.telegram_repo = telegram_repo
        self.notification_repo = notification_repo
        self.incident_repo = incident_repo
        self.user_repo = user_repo
        self.access_control = access_control
        self.telegram_adapter = telegram_adapter

    def _effective_settings(self) -> tuple[TelegramSettings, str]:
        db_cfg = self.telegram_repo.get_settings()
        env_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        if db_cfg.bot_token.strip():
            token_source = "db"
            effective_token = db_cfg.bot_token.strip()
        elif env_token:
            token_source = "env"
            effective_token = env_token
        else:
            token_source = "none"
            effective_token = ""

        env_secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
        env_base_url = os.environ.get("APP_BASE_URL", "").strip()
        enabled = db_cfg.enabled and _env_bool("TELEGRAM_ENABLED", True)

        effective = TelegramSettings(
            id=1,
            bot_token=effective_token,
            enabled=enabled,
            webhook_secret=db_cfg.webhook_secret.strip() or env_secret,
            app_base_url=(db_cfg.app_base_url.strip() or env_base_url).rstrip("/"),
            notify_on_create=db_cfg.notify_on_create,
            notify_on_status=db_cfg.notify_on_status,
            notify_on_escalation=db_cfg.notify_on_escalation,
            updated_at=db_cfg.updated_at,
        )
        return effective, token_source

    def _validate_role_pdn(self, role: str, include_pdn: bool) -> None:
        if not include_pdn or not role:
            return
        synthetic = User(id=0, username="tg", full_name="Telegram", role=Role(role), active=True)
        if not self.access_control.can_view_pdn(synthetic):
            raise ValidationError(
                f"Роль '{role}' не имеет доступа к инцидентам с ПДн; включение include_pdn запрещено"
            )

    def _active_targets(self) -> list[TelegramSubscription]:
        subs = self.telegram_repo.list_subscriptions(active_only=True)
        if subs:
            return subs
        env_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not env_chat_id:
            return []
        return [
            TelegramSubscription(
                id=0,
                chat_id=env_chat_id,
                label="Default (ENV)",
                role="",
                min_severity=_normalize_severity(os.environ.get("TELEGRAM_MIN_SEVERITY"), Severity.LOW),
                notify_on_create=True,
                notify_on_status=True,
                notify_on_escalation=True,
                include_pdn=_env_bool("TELEGRAM_INCLUDE_PDN", False),
                active=True,
            )
        ]

    def _can_deliver(
        self,
        sub: TelegramSubscription,
        incident: Incident,
        event: str | None,
    ) -> bool:
        if not sub.active:
            return False
        if event == "create" and not sub.notify_on_create:
            return False
        if event == "status" and not sub.notify_on_status:
            return False
        if event == "escalation" and not sub.notify_on_escalation:
            return False

        try:
            inc_weight = Severity.normalize(incident.severity).weight
            min_weight = Severity.normalize(sub.min_severity).weight
        except ValueError:
            inc_weight, min_weight = Severity.MEDIUM.weight, Severity.LOW.weight
        if inc_weight < min_weight:
            return False

        has_pdn = PdnFlag.from_bool_int(incident.has_personal_data) is PdnFlag.YES
        if has_pdn and not sub.include_pdn:
            return False

        if sub.role:
            synthetic = User(
                id=0,
                username=f"tg:{sub.chat_id}",
                full_name=sub.label or sub.chat_id,
                role=Role(sub.role),
                active=True,
            )
            if not self.access_control.can_view(synthetic, incident):
                return False

        return True

    def _can_send_via_adapter(self, settings: TelegramSettings) -> bool:
        if self.telegram_adapter is None or not settings.enabled:
            return False
        if settings.bot_token:
            return True
        # Allow unit tests with custom transport or explicit in-memory adapter testing
        return self.telegram_adapter._transport is not None

    def _incident_link_line(self, incident_id: int | None, app_base_url: str) -> str:
        if not app_base_url or incident_id is None:
            return ""
        url = html.escape(f"{app_base_url}/?incident={incident_id}")
        return f'\n🔗 <a href="{url}">Открыть карточку инцидента</a>'

    def _format_created_message(self, incident: Incident, app_base_url: str) -> str:
        pdn_line = (
            "\n⚠️ <b>Затрагивает ПДн</b> (контроль сроков РКН 24/72ч)"
            if PdnFlag.from_bool_int(incident.has_personal_data) is PdnFlag.YES
            else ""
        )
        assignee_line = ""
        if incident.assigned_to is not None:
            assignee = self.user_repo.get_by_id(incident.assigned_to)
            if assignee is not None:
                assignee_line = f"\n👤 <b>Ответственный:</b> {html.escape(assignee.display_label)}"

        lines = [
            f"<b>{_severity_label(incident.severity)} | Новый инцидент #{incident.id}</b>",
            f"📌 <b>{html.escape(incident.title)}</b>",
            f"🏷 <b>Тип:</b> {html.escape(incident.incident_type)}",
            f"📊 <b>Статус:</b> {html.escape(_status_label(incident.status))}",
        ]
        if incident.source:
            lines.append(f"📡 <b>Источник:</b> {html.escape(incident.source)}")
        if incident.computer:
            lines.append(f"💻 <b>Узел:</b> <code>{html.escape(incident.computer)}</code>")
        if incident.employee:
            lines.append(f"🧑‍💼 <b>Сотрудник:</b> {html.escape(incident.employee)}")
        if assignee_line:
            lines.append(assignee_line.lstrip("\n"))
        if pdn_line:
            lines.append(pdn_line.lstrip("\n"))
        if incident.description:
            lines.append(f"\n📝 {html.escape(_truncate(incident.description))}")
        link = self._incident_link_line(incident.id, app_base_url)
        if link:
            lines.append(link.lstrip("\n"))
        return "\n".join(lines)

    def _format_status_message(
        self,
        incident: Incident,
        old_status: str,
        actor: User | None,
        app_base_url: str,
    ) -> str:
        header_icon = "✅" if incident.status == IncidentStatus.CLOSED.value else "🔄"
        lines = [
            f"<b>{header_icon} Инцидент #{incident.id}: статус изменён</b>",
            f"📌 <b>{html.escape(incident.title)}</b>",
            f"📍 <b>Переход:</b> {html.escape(old_status)} → <b>{html.escape(_status_label(incident.status))}</b>",
            f"⚡ <b>Критичность:</b> {_severity_label(incident.severity)} | <b>Тип:</b> {html.escape(incident.incident_type)}",
        ]
        if incident.computer:
            lines.append(f"💻 <b>Узел:</b> <code>{html.escape(incident.computer)}</code>")
        if incident.outcome:
            lines.append(f"📋 <b>Итог:</b> {html.escape(_truncate(incident.outcome, 250))}")
        if actor is not None:
            lines.append(f"👤 <b>Изменил:</b> {html.escape(actor.display_label)}")
        link = self._incident_link_line(incident.id, app_base_url)
        if link:
            lines.append(link.lstrip("\n"))
        return "\n".join(lines)

    def _deliver_to_target(
        self,
        *,
        settings: TelegramSettings,
        sub: TelegramSubscription,
        incident_id: int | None,
        kind: str,
        html_text: str,
        plain_summary: str,
    ) -> dict[str, Any]:
        delivered = False
        error_text: str | None = None
        if self.telegram_adapter is not None:
            try:
                delivered = self.telegram_adapter.send_message(
                    sub.chat_id,
                    html_text,
                    bot_token=settings.bot_token or None,
                    parse_mode="HTML",
                )
                if not delivered:
                    error_text = self.telegram_adapter.last_error or "Telegram send failed"
            except Exception as exc:
                delivered = False
                error_text = str(exc)

        status = DeliveryStatus.SENT.value if delivered else DeliveryStatus.FAILED.value
        notif = self.notification_repo.create(
            incident_id=incident_id,
            recipient_role=sub.role or "telegram",
            recipient_name=sub.label or sub.chat_id,
            kind=kind,
            message=plain_summary,
            created_at=utc_now(),
            channel=Channel.TELEGRAM.value,
            status=status,
        )
        result = notif.to_dict()
        result["chat_id"] = sub.chat_id
        if error_text:
            result["error"] = error_text
        return result

    # --- Public incident & status notification hooks ---

    def notify_incident_created(self, incident: Incident) -> list[dict[str, Any]]:
        """Send Telegram notifications for a newly created incident to matching chats."""
        settings, _ = self._effective_settings()
        if not settings.notify_on_create or not self._can_send_via_adapter(settings):
            return []

        targets = [
            sub
            for sub in self._active_targets()
            if self._can_deliver(sub, incident, "create")
        ]
        if not targets:
            return []

        html_text = self._format_created_message(incident, settings.app_base_url)
        summary = (
            f"Новый инцидент #{incident.id} «{incident.title}» "
            f"({incident.incident_type}, {incident.severity})"
        )
        return [
            self._deliver_to_target(
                settings=settings,
                sub=sub,
                incident_id=incident.id,
                kind="tg_incident_created",
                html_text=html_text,
                plain_summary=summary,
            )
            for sub in targets
        ]

    def notify_status_changed(
        self,
        incident: Incident,
        old_status: str,
        actor: User | None = None,
    ) -> list[dict[str, Any]]:
        """Send Telegram notifications when an incident changes lifecycle status."""
        if old_status == incident.status:
            return []
        settings, _ = self._effective_settings()
        if not settings.notify_on_status or not self._can_send_via_adapter(settings):
            return []

        targets = [
            sub
            for sub in self._active_targets()
            if self._can_deliver(sub, incident, "status")
        ]
        if not targets:
            return []

        html_text = self._format_status_message(incident, old_status, actor, settings.app_base_url)
        summary = (
            f"Статус инцидента #{incident.id} «{incident.title}»: "
            f"{old_status} → {incident.status}"
        )
        return [
            self._deliver_to_target(
                settings=settings,
                sub=sub,
                incident_id=incident.id,
                kind="tg_incident_status",
                html_text=html_text,
                plain_summary=summary,
            )
            for sub in targets
        ]

    def notify_escalation(
        self,
        incident: Incident | None,
        recipient_role: Role | str,
        kind: str,
        message: str,
    ) -> list[dict[str, Any]]:
        """Deliver escalation or urgent notices to matching Telegram subscribers."""
        settings, _ = self._effective_settings()
        if not settings.notify_on_escalation or not self._can_send_via_adapter(settings):
            return []

        role_val = recipient_role.value if isinstance(recipient_role, Role) else str(recipient_role)
        results: list[dict[str, Any]] = []
        for sub in self._active_targets():
            if not sub.notify_on_escalation:
                continue
            if sub.role and sub.role != role_val:
                continue
            if incident is not None and not self._can_deliver(sub, incident, "escalation"):
                continue

            inc_id = incident.id if incident is not None else None
            prefix = f"🚨 <b>Срочное уведомление</b>"
            if inc_id is not None:
                prefix += f" (инцидент #{inc_id})"
            html_text = f"{prefix}\n{html.escape(message)}{self._incident_link_line(inc_id, settings.app_base_url)}"
            results.append(
                self._deliver_to_target(
                    settings=settings,
                    sub=sub,
                    incident_id=inc_id,
                    kind=f"tg_{kind}",
                    html_text=html_text,
                    plain_summary=message,
                )
            )
        return results

    # --- Management & setup API ---

    def get_config(self, user: User | Mapping[str, Any]) -> dict[str, Any]:
        """Return masked Telegram configuration and subscription summary."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        settings, token_source = self._effective_settings()
        subs = self.telegram_repo.list_subscriptions()
        env_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        data = settings.to_dict(mask_secrets=True)
        data["token_source"] = token_source
        data["env_chat_id"] = env_chat_id
        data["subscriptions_count"] = len(subs)
        data["active_subscriptions_count"] = sum(1 for s in subs if s.active)
        data["last_error"] = self.telegram_adapter.last_error if self.telegram_adapter else None
        return data

    def update_config(
        self,
        user: User | Mapping[str, Any],
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Update runtime Telegram bot configuration in SQLite."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor, action="update_denied")
        if not isinstance(data, Mapping):
            raise ValidationError("Настройки Telegram должны быть словарём")

        current = self.telegram_repo.get_settings()
        if "bot_token" in data and data["bot_token"] is not None:
            current.bot_token = str(data["bot_token"]).strip()
        if "enabled" in data and data["enabled"] is not None:
            current.enabled = bool(data["enabled"])
        if "webhook_secret" in data and data["webhook_secret"] is not None:
            current.webhook_secret = str(data["webhook_secret"]).strip()
        if "app_base_url" in data and data["app_base_url"] is not None:
            current.app_base_url = str(data["app_base_url"]).strip().rstrip("/")
        if "notify_on_create" in data and data["notify_on_create"] is not None:
            current.notify_on_create = bool(data["notify_on_create"])
        if "notify_on_status" in data and data["notify_on_status"] is not None:
            current.notify_on_status = bool(data["notify_on_status"])
        if "notify_on_escalation" in data and data["notify_on_escalation"] is not None:
            current.notify_on_escalation = bool(data["notify_on_escalation"])
        current.updated_at = utc_now()

        self.telegram_repo.save_settings(current)
        self.access_control.log_access(actor.id, "telegram_config", 1, "update")
        return self.get_config(actor)

    def verify_connection(self, user: User | Mapping[str, Any]) -> dict[str, Any]:
        """Verify Telegram Bot API credentials using getMe."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        settings, token_source = self._effective_settings()
        if self.telegram_adapter is None:
            return {"connected": False, "token_source": token_source, "error": "Telegram adapter unavailable"}
        if not settings.bot_token and self.telegram_adapter._transport is None:
            return {"connected": False, "token_source": token_source, "error": "Токен бота не настроен"}

        res = self.telegram_adapter.get_me(bot_token=settings.bot_token or None)
        if res.get("ok"):
            return {
                "connected": True,
                "token_source": token_source,
                "bot": res.get("result", {}),
                "error": None,
            }
        return {
            "connected": False,
            "token_source": token_source,
            "bot": None,
            "error": res.get("description") or self.telegram_adapter.last_error,
        }

    def discover_chats(
        self,
        user: User | Mapping[str, Any],
        *,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """Discover recent chats that interacted with the bot via getUpdates."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        settings, _ = self._effective_settings()
        if self.telegram_adapter is None:
            return []
        if not settings.bot_token and self.telegram_adapter._transport is None:
            raise ValidationError("Токен Telegram-бота не настроен")

        res = self.telegram_adapter.get_updates(
            offset=offset,
            bot_token=settings.bot_token or None,
        )
        if not res.get("ok"):
            raise ValidationError(
                f"Не удалось получить обновления Telegram: {res.get('description') or 'ошибка API'}"
            )

        existing = {s.chat_id for s in self.telegram_repo.list_subscriptions()}
        chats: dict[str, dict[str, Any]] = {}
        for upd in res.get("result") or []:
            msg = upd.get("message") or upd.get("edited_message") or upd.get("channel_post") or {}
            chat = msg.get("chat") or {}
            if not chat or chat.get("id") is None:
                continue
            chat_id = str(chat["id"])
            title = (
                chat.get("title")
                or " ".join(
                    part for part in (chat.get("first_name"), chat.get("last_name")) if part
                ).strip()
                or chat.get("username")
                or chat_id
            )
            chats[chat_id] = {
                "chat_id": chat_id,
                "type": chat.get("type", ""),
                "title": title,
                "username": chat.get("username") or "",
                "last_text": msg.get("text") or "",
                "update_id": upd.get("update_id"),
                "already_subscribed": chat_id in existing,
            }
        return list(chats.values())

    def setup_webhook(self, user: User | Mapping[str, Any], webhook_url: str) -> dict[str, Any]:
        """Register webhook URL with Telegram Bot API using configured secret."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        cleaned_url = require_non_blank(webhook_url, "webhook_url")
        if not cleaned_url.startswith("https://"):
            raise ValidationError("Webhook URL должен начинаться с https://")
        settings, _ = self._effective_settings()
        if self.telegram_adapter is None:
            raise ValidationError("Telegram-адаптер недоступен")
        if not settings.bot_token and self.telegram_adapter._transport is None:
            raise ValidationError("Токен Telegram-бота не настроен")

        res = self.telegram_adapter.set_webhook(
            cleaned_url,
            secret_token=settings.webhook_secret,
            bot_token=settings.bot_token or None,
        )
        if not res.get("ok"):
            raise ValidationError(
                f"Не удалось установить webhook: {res.get('description') or 'ошибка API'}"
            )
        self.access_control.log_access(actor.id, "telegram_config", 1, "setup_webhook")
        return {"ok": True, "url": cleaned_url, "description": res.get("description", "")}

    def list_subscriptions(self, user: User | Mapping[str, Any]) -> list[dict[str, Any]]:
        """List all configured Telegram subscriptions."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        return [s.to_dict() for s in self.telegram_repo.list_subscriptions()]

    def upsert_subscription(
        self,
        user: User | Mapping[str, Any],
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Create or update a Telegram chat subscription keyed by chat_id."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor, action="edit_denied")
        if not isinstance(data, Mapping):
            raise ValidationError("Данные подписки должны быть словарём")

        chat_id = require_non_blank(str(data.get("chat_id") or ""), "chat_id")
        role = _normalize_optional_role(data.get("role"))
        min_severity = _normalize_severity(data.get("min_severity"), Severity.LOW)
        include_pdn = bool(data.get("include_pdn", False))
        self._validate_role_pdn(role, include_pdn)

        now = utc_now()
        sub = TelegramSubscription(
            id=0,
            chat_id=chat_id,
            label=str(data.get("label") or "").strip(),
            role=role,
            min_severity=min_severity,
            notify_on_create=bool(data.get("notify_on_create", True)),
            notify_on_status=bool(data.get("notify_on_status", True)),
            notify_on_escalation=bool(data.get("notify_on_escalation", True)),
            include_pdn=include_pdn,
            active=bool(data.get("active", True)),
            created_at=now,
            updated_at=now,
        )
        saved = self.telegram_repo.upsert_subscription(sub)
        self.access_control.log_access(actor.id, "telegram_subscription", saved.id, "upsert")
        return saved.to_dict()

    def update_subscription(
        self,
        user: User | Mapping[str, Any],
        sub_id: int,
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Update settings or active state for an existing Telegram subscription."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor, action="edit_denied")
        existing = self.telegram_repo.get_subscription(sub_id)
        if existing is None:
            raise NotFoundError("Подписка Telegram не найдена")
        if not isinstance(data, Mapping):
            raise ValidationError("Данные обновления подписки должны быть словарём")

        if "label" in data and data["label"] is not None:
            existing.label = str(data["label"]).strip()
        if "role" in data:
            existing.role = _normalize_optional_role(data["role"])
        if "min_severity" in data and data["min_severity"] is not None:
            existing.min_severity = _normalize_severity(data["min_severity"], Severity.LOW)
        if "notify_on_create" in data and data["notify_on_create"] is not None:
            existing.notify_on_create = bool(data["notify_on_create"])
        if "notify_on_status" in data and data["notify_on_status"] is not None:
            existing.notify_on_status = bool(data["notify_on_status"])
        if "notify_on_escalation" in data and data["notify_on_escalation"] is not None:
            existing.notify_on_escalation = bool(data["notify_on_escalation"])
        if "include_pdn" in data and data["include_pdn"] is not None:
            existing.include_pdn = bool(data["include_pdn"])
        if "active" in data and data["active"] is not None:
            existing.active = bool(data["active"])

        self._validate_role_pdn(existing.role, existing.include_pdn)
        existing.updated_at = utc_now()
        updated = self.telegram_repo.update_subscription(existing)
        self.access_control.log_access(actor.id, "telegram_subscription", sub_id, "update")
        return updated.to_dict()

    def delete_subscription(self, user: User | Mapping[str, Any], sub_id: int) -> dict[str, Any]:
        """Delete a Telegram chat subscription."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor, action="delete_denied")
        deleted = self.telegram_repo.delete_subscription(sub_id)
        if not deleted:
            raise NotFoundError("Подписка Telegram не найдена")
        self.access_control.log_access(actor.id, "telegram_subscription", sub_id, "delete")
        return {"deleted": True, "id": sub_id}

    def send_test_notification(
        self,
        user: User | Mapping[str, Any],
        *,
        chat_id: str | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Send a test Telegram message to a specific chat or all active subscriptions."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        settings, _ = self._effective_settings()
        if self.telegram_adapter is None:
            raise ValidationError("Telegram-адаптер недоступен")
        if not settings.enabled:
            raise ValidationError("Отправка Telegram-уведомлений отключена в настройках")

        if chat_id and chat_id.strip():
            existing = self.telegram_repo.get_subscription_by_chat_id(chat_id.strip())
            targets = [
                existing
                or TelegramSubscription(
                    id=0,
                    chat_id=chat_id.strip(),
                    label=chat_id.strip(),
                    active=True,
                )
            ]
        else:
            targets = self._active_targets()
            if not targets:
                raise ValidationError("Нет активных Telegram-подписок для тестовой отправки")

        text_body = (message or "").strip() or (
            "Тестовое уведомление ИС ИБ: подключение Telegram-бота работает корректно."
        )
        html_text = f"🔔 <b>Тест уведомлений ИС ИБ</b>\n{html.escape(text_body)}"
        results = [
            self._deliver_to_target(
                settings=settings,
                sub=sub,
                incident_id=None,
                kind="tg_test",
                html_text=html_text,
                plain_summary=text_body,
            )
            for sub in targets
        ]
        sent_count = sum(1 for r in results if r["status"] == DeliveryStatus.SENT.value)
        failed_count = len(results) - sent_count
        return {
            "ok": failed_count == 0 and sent_count > 0,
            "sent": sent_count,
            "failed": failed_count,
            "results": results,
        }

    # --- Incoming bot updates & commands ---

    def verify_webhook_secret(self, header_secret: str | None) -> bool:
        """Verify Telegram X-Telegram-Bot-Api-Secret-Token header if configured."""
        settings, _ = self._effective_settings()
        expected = settings.webhook_secret.strip()
        if not expected:
            return True
        return bool(header_secret and header_secret.strip() == expected)

    def handle_update(self, update: Mapping[str, Any]) -> dict[str, Any]:
        """Process an incoming Telegram bot update (/start, /help, /status <id>)."""
        if not isinstance(update, Mapping):
            return {"handled": False, "reason": "invalid_update"}
        msg = update.get("message") or update.get("edited_message")
        if not isinstance(msg, Mapping):
            return {"handled": False, "reason": "no_message"}

        chat = msg.get("chat") or {}
        if not isinstance(chat, Mapping) or chat.get("id") is None:
            return {"handled": False, "reason": "no_chat"}

        chat_id = str(chat["id"])
        text = str(msg.get("text") or "").strip()
        if not text.startswith("/"):
            return {"handled": False, "chat_id": chat_id, "reason": "not_command"}

        cmd_parts = text.split(maxsplit=1)
        cmd = cmd_parts[0].split("@", 1)[0].lower()
        arg = cmd_parts[1].strip() if len(cmd_parts) > 1 else ""

        settings, _ = self._effective_settings()
        sub = self.telegram_repo.get_subscription_by_chat_id(chat_id)

        if cmd == "/start":
            status_text = (
                f"Подписка активна (роль: {html.escape(sub.role or 'общий канал')}, мин. важность: {html.escape(sub.min_severity)})."
                if (sub is not None and sub.active)
                else "Подписка ещё не активирована. Передайте этот ID администратору ИБ для подключения."
            )
            reply = (
                f"🤖 <b>Бот уведомлений ИС ИБ</b>\n"
                f"Ваш <code>chat_id</code>: <code>{html.escape(chat_id)}</code>\n"
                f"{status_text}"
            )
        elif cmd == "/help":
            reply = (
                "<b>Доступные команды:</b>\n"
                "/start — показать ваш chat_id и статус подписки\n"
                "/status &lt;ID&gt; — текущий статус инцидента (для активных подписчиков)\n"
                "/help — справка"
            )
        elif cmd == "/status":
            reply = self._build_status_reply(sub, arg)
        else:
            reply = "Неизвестная команда. Используйте /help."

        sent = False
        if self.telegram_adapter is not None and (settings.bot_token or self.telegram_adapter._transport is not None):
            sent = self.telegram_adapter.send_message(
                chat_id,
                reply,
                bot_token=settings.bot_token or None,
                parse_mode="HTML",
            )
        return {"handled": True, "command": cmd, "chat_id": chat_id, "replied": sent, "reply": reply}

    def _build_status_reply(self, sub: TelegramSubscription | None, raw_id: str) -> str:
        if sub is None or not sub.active:
            return "⛔ Чат не подключён к активной подписке уведомлений."
        if not raw_id.isdigit():
            return "Укажите номер инцидента, например: <code>/status 1</code>"
        incident = self.incident_repo.get_by_id(int(raw_id))
        if incident is None or not self._can_deliver(sub, incident, event=None):
            return f"Инцидент #{html.escape(raw_id)} не найден или недоступен для вашей подписки."
        lines = [
            f"<b>Инцидент #{incident.id}: {html.escape(incident.title)}</b>",
            f"📊 <b>Статус:</b> {html.escape(_status_label(incident.status))}",
            f"⚡ <b>Критичность:</b> {_severity_label(incident.severity)}",
            f"🏷 <b>Тип:</b> {html.escape(incident.incident_type)}",
        ]
        if incident.outcome:
            lines.append(f"📋 <b>Итог:</b> {html.escape(_truncate(incident.outcome, 200))}")
        return "\n".join(lines)

    def poll_updates(
        self,
        user: User | Mapping[str, Any],
        *,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Fetch updates via getUpdates and process bot commands."""
        actor = coerce_user(user)
        self.access_control.assert_telegram_manage_access(actor)
        settings, _ = self._effective_settings()
        if self.telegram_adapter is None:
            raise ValidationError("Telegram-адаптер недоступен")
        if not settings.bot_token and self.telegram_adapter._transport is None:
            raise ValidationError("Токен Telegram-бота не настроен")

        res = self.telegram_adapter.get_updates(
            offset=offset,
            bot_token=settings.bot_token or None,
        )
        if not res.get("ok"):
            raise ValidationError(
                f"Не удалось получить обновления Telegram: {res.get('description') or 'ошибка API'}"
            )
        updates = res.get("result") or []
        processed = [self.handle_update(upd) for upd in updates]
        next_offset = (
            max((int(u["update_id"]) for u in updates if "update_id" in u), default=-1) + 1
            if updates
            else offset
        )
        return {
            "received": len(updates),
            "handled": sum(1 for p in processed if p.get("handled")),
            "next_offset": next_offset,
            "results": processed,
        }
