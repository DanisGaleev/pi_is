from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from app.container import container
from auth import get_current_user
from routers import call_service

router = APIRouter(prefix="/api/telegram", tags=["telegram"])


class TelegramConfigUpdate(BaseModel):
    bot_token: str | None = None
    enabled: bool | None = None
    webhook_secret: str | None = None
    app_base_url: str | None = None
    notify_on_create: bool | None = None
    notify_on_status: bool | None = None
    notify_on_escalation: bool | None = None


class TelegramSubscriptionCreate(BaseModel):
    chat_id: str
    label: str = ""
    role: str = ""
    min_severity: str = "low"
    notify_on_create: bool = True
    notify_on_status: bool = True
    notify_on_escalation: bool = True
    include_pdn: bool = False
    active: bool = True


class TelegramSubscriptionUpdate(BaseModel):
    label: str | None = None
    role: str | None = None
    min_severity: str | None = None
    notify_on_create: bool | None = None
    notify_on_status: bool | None = None
    notify_on_escalation: bool | None = None
    include_pdn: bool | None = None
    active: bool | None = None


class TelegramTestRequest(BaseModel):
    chat_id: str | None = None
    message: str | None = None


class TelegramWebhookSetup(BaseModel):
    webhook_url: str


@router.get("/config")
def get_telegram_config(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return call_service(container.telegram_service.get_config, user)


@router.put("/config")
def update_telegram_config(
    payload: TelegramConfigUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.telegram_service.update_config,
        user,
        payload.model_dump(exclude_unset=True),
    )


@router.post("/verify")
def verify_telegram_connection(
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.telegram_service.verify_connection, user)


@router.get("/discover")
def discover_telegram_chats(
    offset: int | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(container.telegram_service.discover_chats, user, offset=offset)


@router.post("/webhook/setup")
def setup_telegram_webhook(
    payload: TelegramWebhookSetup,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.telegram_service.setup_webhook, user, payload.webhook_url)


@router.post("/webhook")
def telegram_webhook(
    payload: dict[str, Any],
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
) -> dict[str, Any]:
    if not container.telegram_service.verify_webhook_secret(x_telegram_bot_api_secret_token):
        raise HTTPException(status_code=403, detail="Неверный секрет Telegram webhook")
    return call_service(container.telegram_service.handle_update, payload)


@router.post("/poll")
def poll_telegram_updates(
    offset: int | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.telegram_service.poll_updates, user, offset=offset)


@router.get("/subscriptions")
def list_telegram_subscriptions(
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return call_service(container.telegram_service.list_subscriptions, user)


@router.post("/subscriptions")
def upsert_telegram_subscription(
    payload: TelegramSubscriptionCreate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.telegram_service.upsert_subscription,
        user,
        payload.model_dump(),
    )


@router.patch("/subscriptions/{sub_id}")
def update_telegram_subscription(
    sub_id: int,
    payload: TelegramSubscriptionUpdate,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.telegram_service.update_subscription,
        user,
        sub_id,
        payload.model_dump(exclude_unset=True),
    )


@router.delete("/subscriptions/{sub_id}")
def delete_telegram_subscription(
    sub_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(container.telegram_service.delete_subscription, user, sub_id)


@router.post("/test")
def test_telegram_notification(
    payload: TelegramTestRequest,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    return call_service(
        container.telegram_service.send_test_notification,
        user,
        chat_id=payload.chat_id,
        message=payload.message,
    )
