"""登录、角色与只读零写闸门。

只读零写册（甲路径）：role 为「只读」时，所有写入口在鉴权前置处整笔拒绝；
正式业务表零改，仅落一条 `write_denied` 拒权审计。
口径锁定 2026-11-21，当日不得改口，也不得与乙路径（审批后服务端代写）混用。
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from db import connect, sha_password, write_audit

SESSIONS: dict[str, str] = {}
router = APIRouter(tags=["auth"])

# —— 只读零写册锁定项，见 ops/只读零写册.md ——
WRITE_POLICY = "甲-鉴权前置整笔拒绝"
WRITE_POLICY_LOCKED_ON = "2026-11-21"
READONLY_ROLE = "只读"
WRITER_ROLES = frozenset({"管理员", "关账员"})


class LoginIn(BaseModel):
    username: str
    password: str


def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    token = authorization.removeprefix("Bearer ").strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(401, "登录已失效")
    return user


def role_of(conn, username: str) -> str | None:
    row = conn.execute(
        "SELECT role FROM users WHERE username=?", (username,)
    ).fetchone()
    return row["role"] if row else None


def _observe_contention(conn, lock_key: str, username: str) -> None:
    """只读后到同窗：不改业务，仅在争用流水里记一笔。"""
    row = conn.execute(
        "SELECT holder FROM window_locks WHERE lock_key=?", (lock_key,)
    ).fetchone()
    if row and row["holder"] != username:
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            """INSERT INTO contention_log(lock_key,actor,action,detail,created_at)
               VALUES (?,?,?,?,?)""",
            (lock_key, username, "争用", f"持有者={row['holder']}", now),
        )


def authorize_write(
    conn,
    authorization: str | None,
    *,
    attempt: str,
    target: str | None = None,
    lock_key: str | None = None,
) -> str:
    """写入口唯一前置：写角色放行；只读整笔拒绝并落拒权审计。

    必须在任何业务表写入之前调用。只读分支只允许写 contention_log 与
    audit_trail 两处旁证，业务表零改。
    """
    username = require_user(authorization)
    role = role_of(conn, username)
    if role in WRITER_ROLES:
        return username

    if lock_key:
        _observe_contention(conn, lock_key, username)
    write_audit(
        conn,
        username,
        "write_denied",
        target,
        {
            "attempt": attempt,
            "role": role,
            "lock_key": lock_key,
            "policy": WRITE_POLICY,
            "locked_on": WRITE_POLICY_LOCKED_ON,
        },
    )
    conn.commit()
    raise HTTPException(403, f"只读零写：{attempt} 整笔拒绝")


def write_gated(fn):
    """给写入口打标：新增写路由若漏标，测试会拦下。"""
    fn.__write_gated__ = True
    return fn


AuthHeader = Annotated[str | None, Header()]


@router.post("/api/login")
def login(body: LoginIn):
    with connect() as conn:
        row = conn.execute(
            "SELECT username,role FROM users WHERE username=? AND password_sha=?",
            (body.username, sha_password(body.password)),
        ).fetchone()
        if not row:
            raise HTTPException(401, "账号或密码错误")
        token = secrets.token_hex(16)
        SESSIONS[token] = row["username"]
        write_audit(conn, row["username"], "login", "session", {"role": row["role"]})
        conn.commit()
    return {"token": token, "username": row["username"], "role": row["role"]}


@router.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    with connect() as conn:
        row = conn.execute(
            "SELECT username,role FROM users WHERE username=?", (user,)
        ).fetchone()
    return dict(row) if row else {"username": user, "role": "未知"}


@router.get("/api/write-policy")
def write_policy(authorization: str | None = Header(default=None)):
    """只读零写册可核证面：角色与口径同源。"""
    require_user(authorization)
    return {
        "policy": WRITE_POLICY,
        "locked_on": WRITE_POLICY_LOCKED_ON,
        "readonly_role": READONLY_ROLE,
        "writer_roles": sorted(WRITER_ROLES),
        "denial_action": "write_denied",
    }
