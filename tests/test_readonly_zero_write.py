"""只读零写回归：先见红，后落鉴权前置零写。

口径见 `ops/只读零写册.md`（甲路径：auth 前置整笔拒绝 + 拒权审计）。
本文件的两条失败测必须在改 auth/windows_svc/materialize_svc 之前先见红。
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import app, init_db
from db import connect


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("db.DB_PATH", tmp_path / "readonly.db")
    init_db()
    yield


def _login(c: TestClient, username: str, password: str) -> dict:
    token = c.post(
        "/api/login", json={"username": username, "password": password}
    ).json()["token"]
    return {"Authorization": "Bearer " + token}


def _rows(table: str) -> list[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]


def _window(wid: int) -> dict:
    with connect() as conn:
        return dict(
            conn.execute("SELECT * FROM windows WHERE id=?", (wid,)).fetchone()
        )


def _role(username: str) -> str:
    with connect() as conn:
        return conn.execute(
            "SELECT role FROM users WHERE username=?", (username,)
        ).fetchone()["role"]


def _denials(actor: str) -> list[dict]:
    out = []
    for row in _rows("audit_trail"):
        if row["action"] != "write_denied" or row["actor"] != actor:
            continue
        out.append(json.loads(row["payload"] or "{}"))
    return out


def test_viewer_close_materialize_ingest_denied_zero_write():
    """红测一：只读关窗/物化/入账必须整笔拒绝，正式数据零改并留拒权审计。"""
    c = TestClient(app)
    admin = _login(c, "admin", "123456")
    viewer = _login(c, "viewer", "view123")

    assert _role("viewer") == "只读"
    assert _window(2)["status"] == "开启"
    mats_before = len(_rows("materializations"))
    events_before = len(_rows("events"))

    r = c.post("/api/windows/2/close", headers=viewer)
    assert r.status_code == 403, f"只读关窗未被拒：{r.status_code} {r.text}"
    assert _window(2)["status"] == "开启", "只读关窗竟改了窗口状态"

    r = c.post("/api/windows/1/materialize", headers=viewer)
    assert r.status_code == 403, f"只读物化未被拒：{r.status_code} {r.text}"
    assert len(_rows("materializations")) == mats_before, "只读物化竟落了物化行"

    r = c.post(
        "/api/events",
        headers=viewer,
        json={
            "window_name": "W-1102",
            "biz_key": "VIEWER-WRITE",
            "event_ts": "2026-11-02T12:00:00",
            "amount": 8,
        },
    )
    assert r.status_code == 403, f"只读入账未被拒：{r.status_code} {r.text}"
    assert len(_rows("events")) == events_before, "只读入账竟落了事件行"

    attempts = {d.get("attempt") for d in _denials("viewer")}
    assert {"window_close", "materialize", "ingest"} <= attempts, attempts

    # 管理员仍可完成关窗 + 物化，证明拒的是角色不是功能
    assert c.post("/api/windows/2/close", headers=admin).status_code == 200
    assert c.post("/api/windows/2/materialize", headers=admin).status_code == 200

    # 关账员是登记在册的写角色，不能被只读零写册误伤
    closer = _login(c, "closer", "close123")
    assert c.post("/api/windows/3/close", headers=closer).status_code == 200


def test_viewer_admin_contention_same_window_lock():
    """红测二：只读与管理抢写同窗须占窗锁；后到只记争用，五处同态。"""
    c = TestClient(app)
    admin = _login(c, "admin", "123456")
    viewer = _login(c, "viewer", "view123")

    mats_before = len(_rows("materializations"))
    assert _window(2)["status"] == "开启"

    # 管理先占同窗窗锁（表示正在写）
    assert (
        c.post(
            "/api/locks/acquire", headers=admin, json={"lock_key": "window:2"}
        ).status_code
        == 200
    )

    # 只读后到抢写同窗：零业务写、只记争用 + 拒权审计
    r = c.post("/api/windows/2/close", headers=viewer)
    assert r.status_code == 403, f"只读抢写未被拒：{r.status_code} {r.text}"

    # 五处同态：角色 / 拒权审计 / 窗口状态 / 物化 / 争用
    assert _role("viewer") == "只读"
    assert any(d.get("attempt") == "window_close" for d in _denials("viewer"))
    assert _window(2)["status"] == "开启", "后到只读竟改了窗口状态"
    assert len(_rows("materializations")) == mats_before
    contention = [x for x in _rows("contention_log") if x["lock_key"] == "window:2"]
    assert any(x["actor"] == "viewer" for x in contention), contention

    # 持锁的管理继续完成关窗；窗锁在其事务结束后释放
    assert c.post("/api/windows/2/close", headers=admin).status_code == 200
    assert _window(2)["status"] == "已关闭"

    # 已关窗后只读物化仍须拒绝，且不得新增物化行
    mats_closed = len(_rows("materializations"))
    r = c.post("/api/windows/2/materialize", headers=viewer)
    assert r.status_code == 403, f"只读物化未被拒：{r.status_code} {r.text}"
    assert len(_rows("materializations")) == mats_closed

    # 管理物化成功，证明同窗写路径仍可用
    assert c.post("/api/windows/2/materialize", headers=admin).status_code == 200
    assert len(_rows("materializations")) == mats_closed + 1


def test_readonly_zero_write_covers_every_write_endpoint():
    """只读零写册是「零写」而不是「三处特判」：其余写入口同样整笔拒绝。"""
    c = TestClient(app)
    viewer = _login(c, "viewer", "view123")

    protected_tables = (
        "windows",
        "events",
        "materializations",
        "hold_staging",
        "late_bucket",
        "reopen_ledger",
        "reject_slips",
        "window_locks",
    )
    before = {t: len(_rows(t)) for t in protected_tables}

    attempts = [
        (
            "/api/windows",
            {"name": "W-VIEWER", "open_at": "2026-11-09T00:00:00", "close_at": "2026-11-09T23:59:59"},
        ),
        (
            "/api/holds",
            {
                "window_name": "W-1102",
                "biz_key": "H-VIEWER",
                "event_ts": "2026-11-02T15:00:00",
                "amount": 1.5,
            },
        ),
        (
            "/api/late-bucket/promote-stub",
            {"late_id": 1, "target_window_name": "W-1102"},
        ),
        ("/api/late-bucket/1/discard-stub", {}),
        ("/api/windows/2/reopen-stub", {"mode": "作废重算"}),
        ("/api/materializations/partition-stub", {}),
        ("/api/locks/acquire", {"lock_key": "window:2"}),
    ]
    for path, body in attempts:
        r = c.post(path, headers=viewer, json=body)
        assert r.status_code == 403, f"{path} 只读未被拒：{r.status_code} {r.text}"

    after = {t: len(_rows(t)) for t in protected_tables}
    assert after == before, f"只读写入了受保护表：{before} -> {after}"


WRITE_ROUTE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _walk_routes(routes):
    """FastAPI 新版会把 include_router 收成 _IncludedRouter，需下钻。"""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _walk_routes(inner.routes)
        else:
            yield route


def test_every_write_route_is_gated():
    """写路由清单守卫：任何新增写入口必须打上 authorize_write 前置闸门，否则本测见红。"""
    gated_routes = set()
    for route in _walk_routes(app.routes):
        methods = getattr(route, "methods", None) or set()
        if not methods & WRITE_ROUTE_METHODS:
            continue
        endpoint = route.endpoint
        path = route.path
        if getattr(endpoint, "__write_gated__", False):
            gated_routes.add(path)
            continue
        # 登录是只读零写册之外的会话入口，不在业务写口径内
        assert path == "/api/login", f"写路由漏挂只读零写闸门：{path}"

    # 只读零写册覆盖的业务写面必须齐备（防止删闸/改名遁形）
    assert {
        "/api/windows",
        "/api/windows/{wid}/close",
        "/api/windows/{wid}/materialize",
        "/api/events",
        "/api/holds",
        "/api/holds/{hold_id}/release-stub",
        "/api/late-bucket/promote-stub",
        "/api/late-bucket/{late_id}/discard-stub",
        "/api/windows/{wid}/reopen-stub",
        "/api/materializations/partition-stub",
        "/api/locks/acquire",
        "/api/locks/release",
    } <= gated_routes


