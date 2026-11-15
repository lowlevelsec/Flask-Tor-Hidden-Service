"""Authenticated Flask file and note service for a Tor onion service."""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import click
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import CSRFError
from werkzeug.utils import secure_filename
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Length


csrf = CSRFProtect()
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")

# Deliberately excludes browser-executable formats such as HTML, SVG and JS.
# All downloads are forced to application/octet-stream regardless of extension.
ALLOWED_EXTENSIONS = {
    ".7z", ".bin", ".c", ".cfg", ".conf", ".cpp", ".csv", ".docx", ".pptx",
    ".gif", ".gz", ".h", ".ini", ".iso", ".jpeg", ".jpg", ".json",
    ".log", ".md", ".pdf", ".png", ".py", ".rom", ".rs", ".sql",
    ".tar", ".toml", ".txt", ".webp", ".xlsx", ".xz", ".yaml", ".yml",
    ".zip",
}


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(max=32)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(max=72)],
    )


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_db() -> sqlite3.Connection:
    """Return the current request's SQLite connection."""
    if "db" not in g:
        database = sqlite3.connect(
            current_app.config["DATABASE"],
            timeout=5,
        )
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys = ON")
        g.db = database
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db(app: Flask) -> None:
    """Create the database and private storage directories if missing."""
    database_path = Path(app.config["DATABASE"])
    upload_path = Path(app.config["UPLOAD_FOLDER"])
    database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    upload_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    schema = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash BLOB NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hosted_files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            file_size INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            failures INTEGER NOT NULL,
            last_failed_at INTEGER NOT NULL,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
    """

    with closing(sqlite3.connect(database_path, timeout=5)) as database:
        database.execute("PRAGMA journal_mode = WAL")
        database.executescript(schema)

        # Migrate the original project schema (users.password TEXT) to the
        # current column name. SQLite can store BLOB values in the renamed
        # column even if its legacy declared affinity was TEXT.
        user_columns = {
            row[1] for row in database.execute("PRAGMA table_info(users)").fetchall()
        }
        if "password_hash" not in user_columns and "password" in user_columns:
            database.execute("ALTER TABLE users RENAME COLUMN password TO password_hash")
            user_columns.remove("password")
            user_columns.add("password_hash")
        if "created_at" not in user_columns:
            database.execute(
                "ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
            )

        for user_id, stored_hash in database.execute(
            "SELECT id, password_hash FROM users"
        ).fetchall():
            if isinstance(stored_hash, str):
                database.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (stored_hash.encode("utf-8"), user_id),
                )
        database.commit()

    # Restrict only app-owned directories; never chmod an arbitrary configured
    # database parent such as the project root or a shared system directory.
    if os.name == "posix":
        instance_path = Path(app.instance_path).resolve()
        if database_path.parent.resolve() == instance_path:
            os.chmod(instance_path, 0o700)
        os.chmod(upload_path, 0o700)
        if database_path.exists():
            os.chmod(database_path, 0o600)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def _record_failed_login(username: str, now: int) -> None:
    database = get_db()
    window_start = now - current_app.config["LOGIN_ATTEMPT_RETENTION"]
    database.execute(
        "DELETE FROM login_attempts WHERE last_failed_at < ?",
        (window_start,),
    )
    # Bound database growth when attackers try many different usernames.
    database.execute(
        """DELETE FROM login_attempts
           WHERE username IN (
               SELECT username FROM login_attempts
               ORDER BY last_failed_at DESC LIMIT -1 OFFSET 4096
           )"""
    )
    row = database.execute(
        "SELECT failures, last_failed_at FROM login_attempts WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None or row["last_failed_at"] <= now - current_app.config["LOGIN_LOCKOUT_SECONDS"]:
        failures = 1
    else:
        failures = row["failures"] + 1

    locked_until = (
        now + current_app.config["LOGIN_LOCKOUT_SECONDS"]
        if failures >= current_app.config["LOGIN_MAX_ATTEMPTS"]
        else 0
    )
    database.execute(
        """INSERT INTO login_attempts (username, failures, last_failed_at, locked_until)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
             failures = excluded.failures,
             last_failed_at = excluded.last_failed_at,
             locked_until = excluded.locked_until""",
        (username, failures, now, locked_until),
    )
    database.commit()


def create_app(test_config: dict | None = None) -> Flask:
    """Application factory. A strong SECRET_KEY is mandatory outside tests."""
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)
    env_secret = os.getenv("SECRET_KEY")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=env_secret,
        DATABASE=os.getenv(
            "DATABASE_PATH",
            str(Path(app.instance_path) / "sql_database.db"),
        ),
        UPLOAD_FOLDER=os.getenv(
            "UPLOAD_FOLDER",
            str(Path(app.instance_path) / "uploads"),
        ),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        MAX_STORAGE_BYTES=1024 * 1024 * 1024,
        MAX_FILES=5000,
        MAX_NOTE_LENGTH=2000,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", False),
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_PATH="/",
        SESSION_COOKIE_DOMAIN=None,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False,
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        LOGIN_MAX_ATTEMPTS=5,
        LOGIN_LOCKOUT_SECONDS=900,
        LOGIN_ATTEMPT_RETENTION=86400,
        BCRYPT_ROUNDS=12,
        ENABLE_HSTS=_env_bool("ENABLE_HSTS", False),
    )

    if test_config:
        app.config.update(test_config)

    app.config["SESSION_COOKIE_NAME"] = (
        "__Host-onion_session"
        if app.config["SESSION_COOKIE_SECURE"]
        else "onion_session"
    )

    if app.config["ENABLE_HSTS"] and not app.config["SESSION_COOKIE_SECURE"]:
        raise RuntimeError("ENABLE_HSTS requires SESSION_COOKIE_SECURE=true and HTTPS.")

    secret_key = app.config.get("SECRET_KEY")
    if not isinstance(secret_key, str) or len(secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or too short. Generate one with "
            "`python -c \"import secrets; print(secrets.token_hex(32))\"` "
            "and put it in your untracked .env file."
        )

    Path(app.instance_path).mkdir(mode=0o700, parents=True, exist_ok=True)
    csrf.init_app(app)
    init_db(app)
    app.teardown_appcontext(close_db)

    # Used for unknown usernames so the normal invalid-login path still performs
    # a bcrypt check. It is generated once per worker at the configured cost.
    dummy_password_hash = bcrypt.hashpw(
        b"not-a-real-account-password",
        bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"]),
    )

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'",
        )
        response.headers.setdefault("Cache-Control", "no-store")
        if app.config["ENABLE_HSTS"]:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(_error):
        return render_template("error.html", message="Invalid or expired form token."), 400

    @app.errorhandler(413)
    def request_too_large(_error):
        return render_template("error.html", message="The uploaded request is too large."), 413

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", message="The requested resource was not found."), 404

    @app.get("/")
    @login_required
    def index():
        database = get_db()
        files = database.execute(
            """SELECT id, original_name, file_size, uploaded_by, uploaded_at
               FROM hosted_files ORDER BY uploaded_at DESC, id DESC"""
        ).fetchall()
        notes = database.execute(
            """SELECT username, content, created_at
               FROM notes ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        return render_template(
            "index.html",
            files=files,
            notes=notes,
            max_file_size=app.config["MAX_CONTENT_LENGTH"],
            max_note_length=app.config["MAX_NOTE_LENGTH"],
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("index"))

        form = LoginForm()
        if form.validate_on_submit():
            username = (form.username.data or "").strip().lower()
            password = form.password.data or ""
            password_bytes = password.encode("utf-8")
            now = int(time.time())
            if not USERNAME_RE.fullmatch(username):
                bcrypt.checkpw(password_bytes[:72], dummy_password_hash)
                flash("Invalid username or password.", "error")
                return render_template("login.html", form=form), 401

            database = get_db()
            attempt = database.execute(
                "SELECT locked_until FROM login_attempts WHERE username = ?",
                (username,),
            ).fetchone()

            # Reject overlong bcrypt inputs rather than relying on bcrypt's
            # 72-byte input boundary or silently truncating a password.
            valid_length = 0 < len(password_bytes) <= 72
            locked = bool(attempt and attempt["locked_until"] > now)
            if locked:
                # Do not extend an active lockout on every retry; otherwise an
                # attacker could keep an account locked indefinitely.
                bcrypt.checkpw(password_bytes[:72], dummy_password_hash)
                authenticated_user = None
            else:
                user = database.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                candidate_hash = user["password_hash"] if user else dummy_password_hash
                try:
                    password_ok = (
                        bcrypt.checkpw(password_bytes, candidate_hash)
                        if valid_length
                        else bcrypt.checkpw(password_bytes[:72], dummy_password_hash) and False
                    )
                except (TypeError, ValueError):
                    # A malformed legacy hash must fail closed, not crash login.
                    password_ok = False
                authenticated_user = user if user and password_ok else None

            if authenticated_user:
                database.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
                database.commit()
                session.clear()
                session["user_id"] = authenticated_user["id"]
                session["username"] = authenticated_user["username"]
                session.permanent = True
                return redirect(url_for("index"))

            if not locked:
                _record_failed_login(username, now)
            flash("Invalid username or password.", "error")
            return render_template("login.html", form=form), 401

        return render_template("login.html", form=form)

    @app.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        if request.method == "POST":
            session.clear()
            flash("You have been logged out.", "success")
            return redirect(url_for("login"))
        return render_template("logout.html")

    @app.get("/search")
    @login_required
    def search():
        # Jinja autoescaping is relied on here; never interpolate user data into
        # render_template_string or mark it as safe HTML.
        query = request.args.get("q", "")[:200]
        return render_template("search.html", query=query)

    @app.post("/comment")
    @login_required
    def comment():
        content = request.form.get("comment", "").strip()
        if not content:
            flash("The note cannot be empty.", "error")
        elif len(content) > app.config["MAX_NOTE_LENGTH"]:
            flash("The note is too long.", "error")
        else:
            database = get_db()
            database.execute(
                "INSERT INTO notes (username, content, created_at) VALUES (?, ?, ?)",
                (
                    session.get("username", "unknown"),
                    content,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            # Keep the note table bounded; the dashboard displays the newest 100.
            database.execute(
                "DELETE FROM notes WHERE id NOT IN (SELECT id FROM notes ORDER BY id DESC LIMIT 1000)"
            )
            database.commit()
            flash("Note added.", "success")
        return redirect(url_for("index"))

    @app.post("/upload")
    @login_required
    def upload():
        uploaded_file = request.files.get("file")
        if uploaded_file is None or not uploaded_file.filename:
            flash("Select a file to upload.", "error")
            return redirect(url_for("index"))

        original_name = secure_filename(uploaded_file.filename)
        if not original_name or len(original_name) > 128:
            flash("The filename is invalid or too long.", "error")
            return redirect(url_for("index"))

        extension = Path(original_name).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            flash("This file extension is not allowed.", "error")
            return redirect(url_for("index"))

        file_id = secrets.token_hex(16)
        stored_name = f"{file_id}.blob"
        destination = Path(app.config["UPLOAD_FOLDER"]) / stored_name

        try:
            uploaded_file.save(destination)
            file_size = destination.stat().st_size
            if file_size == 0:
                destination.unlink(missing_ok=True)
                flash("Empty files are not accepted.", "error")
                return redirect(url_for("index"))
            if file_size > app.config["MAX_CONTENT_LENGTH"]:
                destination.unlink(missing_ok=True)
                flash("The file exceeds the upload limit.", "error")
                return redirect(url_for("index"))

            database = get_db()
            # Serialize quota checks and inserts so simultaneous requests cannot
            # exceed the total storage ceiling through a race condition.
            database.execute("BEGIN IMMEDIATE")
            used_bytes = database.execute(
                "SELECT COALESCE(SUM(file_size), 0) AS total FROM hosted_files"
            ).fetchone()["total"]
            file_count = database.execute(
                "SELECT COUNT(*) AS total FROM hosted_files"
            ).fetchone()["total"]
            if used_bytes + file_size > app.config["MAX_STORAGE_BYTES"]:
                database.rollback()
                destination.unlink(missing_ok=True)
                flash("The storage quota has been reached.", "error")
                return redirect(url_for("index"))
            if file_count >= app.config["MAX_FILES"]:
                database.rollback()
                destination.unlink(missing_ok=True)
                flash("The maximum number of hosted files has been reached.", "error")
                return redirect(url_for("index"))

            database.execute(
                """INSERT INTO hosted_files
                   (id, original_name, stored_name, file_size, uploaded_by, uploaded_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    file_id,
                    original_name,
                    stored_name,
                    file_size,
                    session.get("username", "unknown"),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            database.commit()
        except Exception:
            try:
                get_db().rollback()
            except sqlite3.Error:
                pass
            destination.unlink(missing_ok=True)
            current_app.logger.exception("File upload failed")
            abort(500)

        flash("File uploaded.", "success")
        return redirect(url_for("index"))

    @app.get("/files/<file_id>")
    @login_required
    def download_file(file_id: str):
        if not re.fullmatch(r"[a-f0-9]{32}", file_id):
            abort(404)
        database = get_db()
        file_record = database.execute(
            "SELECT original_name, stored_name FROM hosted_files WHERE id = ?",
            (file_id,),
        ).fetchone()
        if file_record is None:
            abort(404)

        path = Path(app.config["UPLOAD_FOLDER"]) / file_record["stored_name"]
        if not path.is_file():
            abort(404)

        # Never render uploads inline. This prevents uploaded HTML/SVG from
        # executing in the application's origin if a file slips into storage.
        return send_file(
            path,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=file_record["original_name"],
            conditional=True,
            max_age=0,
        )

    @app.cli.command("create-user")
    def create_user_command():
        """Create a login account. There is intentionally no public signup route."""
        username = click.prompt("Username").strip().lower()
        if not USERNAME_RE.fullmatch(username):
            raise click.ClickException(
                "Use 3-32 lowercase letters, digits, dots, underscores or hyphens."
            )

        password = click.prompt(
            "Password (12-72 UTF-8 bytes)",
            hide_input=True,
            confirmation_prompt=True,
        )
        password_bytes = password.encode("utf-8")
        if len(password_bytes) < 12 or len(password_bytes) > 72:
            raise click.ClickException("Password must contain 12-72 UTF-8 bytes.")

        password_hash = bcrypt.hashpw(
            password_bytes,
            bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"]),
        )
        with app.app_context():
            database = get_db()
            try:
                database.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (
                        username,
                        password_hash,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ),
                )
                database.commit()
            except sqlite3.IntegrityError as error:
                raise click.ClickException("That username already exists.") from error
        click.echo(f"Created user: {username}")

    @app.cli.command("reset-password")
    def reset_password_command():
        """Reset a user's password from the local command line."""
        username = click.prompt("Username to reset").strip().lower()
        if not USERNAME_RE.fullmatch(username):
            raise click.ClickException("Invalid username format.")
        password = click.prompt(
            "New password (12-72 UTF-8 bytes)",
            hide_input=True,
            confirmation_prompt=True,
        )
        password_bytes = password.encode("utf-8")
        if len(password_bytes) < 12 or len(password_bytes) > 72:
            raise click.ClickException("Password must contain 12-72 UTF-8 bytes.")
        new_hash = bcrypt.hashpw(
            password_bytes,
            bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"]),
        )
        with app.app_context():
            database = get_db()
            cursor = database.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_hash, username),
            )
            database.commit()
            if cursor.rowcount != 1:
                raise click.ClickException("That username does not exist.")
            database.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
            database.commit()
        click.echo(f"Password reset for: {username}")

    return app


app = create_app()


if __name__ == "__main__":
    # Development only. For deployment, use Gunicorn on 127.0.0.1 and let Tor
    # forward the onion virtual port to that private listener.
    app.run(host="127.0.0.1", port=5000, debug=False)
