"""User management (admin only) and self password change.

Authorization is enforced centrally (web/authz.py): every route here is admin-only except
`PUT /users/me/password`, which any live session may call. The handlers add the business rules the
policy cannot express: the uniqueness check, the password policy, and the guard that the system
always keeps at least one enabled admin.
"""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from cyllex_argus.knowledge.models import Role, User
from cyllex_argus.web import auth_core
from cyllex_argus.web.deps import RowId, current_user, open_services
from cyllex_argus.web.security import TOKEN_HEADER

router = APIRouter()


class CreateUserBody(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1024)
    role: Role


class UpdateUserBody(BaseModel):
    role: Role | None = None
    disabled: bool | None = None


class ResetPasswordBody(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class ChangeOwnPasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


def _view(user: User) -> dict:
    return {
        "id": user.id, "username": user.username, "role": user.role.value,
        "disabled": user.disabled, "created_at": user.created_at, "created_by": user.created_by,
    }


def _validate(password: str) -> None:
    try:
        auth_core.validate_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/users")
def list_users(request: Request) -> dict:
    with open_services(request) as services:
        return {"users": [_view(u) for u in services.store.list_users()]}


@router.post("/users", status_code=201)
def create_user(body: CreateUserBody, request: Request) -> dict:
    _validate(body.password)
    actor = current_user(request)
    with open_services(request) as services:
        store = services.store
        if store.get_user_by_username(body.username) is not None:
            raise HTTPException(status_code=409, detail="username already exists")
        try:
            user = store.create_user(
                body.username, auth_core.hash_password(body.password), body.role,
                created_by=actor.id if actor else None,
            )
        except sqlite3.IntegrityError:  # a concurrent create or a casefold collision
            raise HTTPException(status_code=409, detail="username already exists") from None
        return _view(user)


@router.put("/users/me/password", status_code=204)
def change_own_password(body: ChangeOwnPasswordBody, request: Request) -> Response:
    actor = current_user(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="session required")
    _validate(body.new_password)
    with open_services(request) as services:
        store = services.store
        hashed = store.user_password_hash(actor.id) or ""
        if not auth_core.verify_password(body.current_password, hashed):
            raise HTTPException(status_code=400, detail="current password is incorrect")
        store.set_user_password(actor.id, auth_core.hash_password(body.new_password))
        # Changing the password logs out every OTHER device; keep this one signed in.
        presented = request.headers.get(TOKEN_HEADER)
        keep = auth_core.token_hash(presented) if presented else None
        store.delete_user_sessions(actor.id, except_token_hash=keep)
    return Response(status_code=204)


@router.put("/users/{user_id}")
def update_user(user_id: RowId, body: UpdateUserBody, request: Request) -> dict:
    with open_services(request) as services:
        store = services.store
        # The guard and the mutation share one lock so two concurrent requests cannot each demote
        # a different one of the last two admins and leave zero.
        with store.atomic():
            user = store.get_user(user_id)
            if user is None or user.deleted_at:
                raise HTTPException(status_code=404, detail="no such user")
            # Only an *enabled* admin counts toward the invariant, so disabling/demoting an
            # already-disabled admin is allowed.
            loses_admin = (body.role is not None and body.role is not Role.ADMIN) or body.disabled is True
            if user.role is Role.ADMIN and not user.disabled and loses_admin and store.count_enabled_admins() <= 1:
                raise HTTPException(status_code=409, detail="cannot remove the last admin")
            if body.role is not None:
                store.set_user_role(user_id, body.role)
            if body.disabled is not None:
                store.set_user_disabled(user_id, body.disabled)
            return _view(store.get_user(user_id))


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: RowId, request: Request) -> Response:
    with open_services(request) as services:
        store = services.store
        with store.atomic():
            user = store.get_user(user_id)
            if user is None or user.deleted_at:
                raise HTTPException(status_code=404, detail="no such user")
            if user.role is Role.ADMIN and not user.disabled and store.count_enabled_admins() <= 1:
                raise HTTPException(status_code=409, detail="cannot delete the last admin")
            store.delete_user(user_id)
    return Response(status_code=204)


@router.post("/users/{user_id}/password", status_code=204)
def reset_password(user_id: RowId, body: ResetPasswordBody, request: Request) -> Response:
    _validate(body.password)
    with open_services(request) as services:
        store = services.store
        user = store.get_user(user_id)
        if user is None or user.deleted_at:
            raise HTTPException(status_code=404, detail="no such user")
        store.set_user_password(user_id, auth_core.hash_password(body.password))
        store.delete_user_sessions(user_id)  # an admin reset revokes the target's sessions
    return Response(status_code=204)
