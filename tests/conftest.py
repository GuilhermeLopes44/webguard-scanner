from __future__ import annotations

import threading

import pytest
from flask import Flask, redirect, request, session

from core.config import AppConfig
from db.database import init_db


def _make_vuln_app() -> Flask:
    app = Flask("webguard_vuln_fixture")
    app.secret_key = "webguard-test-secret"

    @app.after_request
    def cors(resp):
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/")
    def index():
        return (
            "<html><body>"
            "<a href='/search?q=test'>search</a>"
            "<a href='/go?next=/'>go</a>"
            "<a href='/auth/login'>login</a>"
            "<form method='post' action='/echo'>"
            "<input name='user'><input name='pass'>"
            "</form>"
            "</body></html>"
        )

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        if "'" in q or '"' in q:
            return f"sql syntax error near {q}", 200, {"Content-Type": "text/html"}
        return f"<html><body>Results for {q}</body></html>"

    @app.route("/go")
    def go():
        nxt = request.args.get("next", "/")
        return "", 302, {"Location": nxt}

    @app.route("/echo", methods=["POST"])
    def echo():
        user = request.form.get("user", "")
        return f"<html><body>Welcome {user}</body></html>"

    @app.route("/auth/login", methods=["GET", "POST"])
    def auth_login():
        if request.method == "GET":
            return (
                "<html><body><form method='post' action='/auth/login'>"
                "<input name='username'><input name='password' type='password'>"
                "<button>Login</button></form></body></html>"
            )
        user = request.form.get("username", "")
        password = request.form.get("password", "")
        if user == "admin" and password == "admin123":
            session["user"] = user
            return "<html><body>LOGIN_OK dashboard</body></html>"
        return "<html><body>LOGIN_FAILED</body></html>", 401

    @app.route("/private")
    def private():
        if not session.get("user"):
            return "Unauthorized", 401
        name = request.args.get("name", "guest")
        return (
            f"<html><body>"
            f"Private area for {session['user']}. Hello {name}. "
            f"<a href='/private/search?q=test'>priv search</a>"
            f"</body></html>"
        )

    @app.route("/private/search")
    def private_search():
        if not session.get("user"):
            return "Unauthorized", 401
        q = request.args.get("q", "")
        return f"<html><body>Private results for {q}</body></html>"

    @app.route("/.git/HEAD")
    def git_head():
        return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}

    @app.route("/setcookie")
    def setcookie():
        resp = app.make_response("ok")
        resp.set_cookie("session", "abc")
        return resp

    return app


@pytest.fixture(scope="session")
def vuln_server():
    app = _make_vuln_app()
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=8765, debug=False, use_reloader=False),
        daemon=True,
    )
    server.start()
    import time

    time.sleep(0.8)
    yield "http://127.0.0.1:8765"


@pytest.fixture
def config() -> AppConfig:
    return AppConfig(
        max_pages=8,
        max_depth=2,
        timeout=3,
        rate_limit_rps=20,
        enabled_checks=[
            "security_headers",
            "cookie_flags",
            "tech_detect",
            "xss_reflected",
            "sqli_error",
            "open_redirect",
            "cors_misconfig",
            "sensitive_paths",
            "csrf_heuristic",
        ],
    )


@pytest.fixture(autouse=True)
def _clean_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_webguard.db"
    monkeypatch.setattr("db.database.DB_PATH", db_file)
    init_db()
    yield
