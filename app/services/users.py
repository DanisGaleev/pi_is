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
    """Attach assignees, assigned_to_user, and created_by_user summaries while preserving IDs."""
    items: list[dict[str, Any]] = [
        task.to_dict() if isinstance(task, Task) else dict(task)
        for task in tasks
    ]
    if not items:
        return []

    user_ids: set[int] = set()
    assignees_per_item: list[list[int]] = []
    for item in items:
        raw_ids = item.get("assignee_ids")
        assigned_id = item.get("assigned_to")
        if isinstance(raw_ids, (list, tuple)) and raw_ids:
            norm_ids = list(dict.fromkeys(int(uid) for uid in raw_ids if uid is not None))
        elif assigned_id is not None and not (isinstance(raw_ids, (list, tuple)) and len(raw_ids) == 0):
            norm_ids = [int(assigned_id)]
        else:
            norm_ids = []
        assignees_per_item.append(norm_ids)
        user_ids.update(norm_ids)

        created_id = item.get("created_by")
        if created_id is not None:
            user_ids.add(int(created_id))

    users_by_id = (
        user_repo.get_by_ids(user_ids)
        if (user_repo is not None and user_ids)
        else {}
    )

    for item, norm_ids in zip(items, assignees_per_item):
        primary_id = norm_ids[0] if norm_ids else None
        item["assignee_ids"] = norm_ids
        item["assigned_to"] = primary_id
        item["assignees"] = [
            users_by_id[uid].to_summary_dict()
            for uid in norm_ids
            if uid in users_by_id
        ]
        primary_user = users_by_id.get(primary_id) if primary_id is not None else None
        item["assigned_to_user"] = (
            primary_user.to_summary_dict() if primary_user is not None else None
        )
        created_id = item.get("created_by")
        created_user = (
            users_by_id.get(int(created_id)) if created_id is not None else None
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
