from collections.abc import Iterable, Mapping
from typing import Any

from app.domain.models import Task
from app.enums import Role
from app.repositories.sqlite_repo import UserRepository

ASSIGNABLE_ROLES: tuple[Role, ...] = (
    Role.SYS_ADMIN,
    Role.SECURITY_SPECIALIST,
    Role.IT_HEAD,
    Role.LAWYER,
)


def enrich_tasks_with_users(
    tasks: Iterable[Task | Mapping[str, Any]],
    user_repo: UserRepository | None,
) -> list[dict[str, Any]]:
    """Attach assigned_to_user and created_by_user summaries while preserving IDs."""
    items: list[dict[str, Any]] = [
        task.to_dict() if isinstance(task, Task) else dict(task)
        for task in tasks
    ]
    if not items:
        return []

    user_ids: set[int] = set()
    for item in items:
        assigned_id = item.get("assigned_to")
        created_id = item.get("created_by")
        if assigned_id is not None:
            user_ids.add(int(assigned_id))
        if created_id is not None:
            user_ids.add(int(created_id))

    users_by_id = (
        user_repo.get_by_ids(user_ids)
        if (user_repo is not None and user_ids)
        else {}
    )

    for item in items:
        assigned_id = item.get("assigned_to")
        created_id = item.get("created_by")
        assigned_user = (
            users_by_id.get(int(assigned_id)) if assigned_id is not None else None
        )
        created_user = (
            users_by_id.get(int(created_id)) if created_id is not None else None
        )
        item["assigned_to_user"] = (
            assigned_user.to_summary_dict() if assigned_user is not None else None
        )
        item["created_by_user"] = (
            created_user.to_summary_dict() if created_user is not None else None
        )
    return items


class UserService:
    """User directory and task assignee picker service."""

    def __init__(self, user_repo: UserRepository) -> None:
        self.user_repo = user_repo

    def list_users(
        self,
        role: str | None = None,
        assignable: bool = False,
    ) -> list[dict[str, Any]]:
        """Return formatted user records filtered by role and/or assignable flag."""
        users = self.user_repo.list_filtered(
            role=role,
            roles=ASSIGNABLE_ROLES if assignable else None,
            active_only=assignable,
        )
        return [u.to_picker_dict() for u in users]
