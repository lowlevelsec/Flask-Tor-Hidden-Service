# Flask Hidden Onion Service

A lightweight Flask-based, authenticated file and note service intended to run behind a Tor v3 Onion Service. It has no public registration route: accounts are created locally through the Flask CLI.

> **Security scope:** this is a hardened flask project, not “bulletproof” or independently security-audited software. A secure application still depends on the host OS, deployment configuration, dependency patching, operator practices and threat model.

## Features

- Login-only access; no public signup endpoint.
- SQLite-backed accounts, shared notes, upload metadata and login throttling.
- bcrypt password hashes (12 rounds by default).
- CSRF protection on all state-changing requests.
- Parameterized SQL queries and Jinja autoescaping.
- Authenticated file uploads and downloads; uploads are stored outside the web root under random server-side names.
- Extension allowlist, 16 MiB per-request limit, 1 GiB total storage quota, 5,000-file cap and forced `application/octet-stream` attachment downloads.
- HTTP security headers, restrictive Content Security Policy and no-store caching.
- Secure cookie defaults, configurable for the HTTP browser-facing origin used by a typical Onion Service.

## Project layout

```text
flask-onion-vault/
├── flask_server.py
├── requirements.txt
├── requirements-dev.txt
├── requirements-production.txt
├── host_onion_service.sh
├── .env.example
├── .gitignore
├── README.md
├── instance/
│   └── .gitkeep
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── error.html
│   ├── index.html
│   ├── login.html
│   ├── logout.html
│   └── search.html
└── tests/
    └── test_app.py
```

Runtime data is deliberately **not** committed: SQLite lives at `instance/sql_database.db` and uploaded blobs at `instance/uploads/` by default. The old project-root `sql_database.db` should be removed from Git tracking and should not be committed. If it contains existing accounts you intend to keep, back it up and move/copy it to `instance/sql_database.db` before starting the new version; the startup migration renames the legacy `users.password` column to `password_hash` and converts textual bcrypt hashes to bytes. Malformed or plaintext legacy passwords will not authenticate; reset those locally with `flask --app flask_server reset-password`.

## Local setup

Python 3.10 or newer is recommended.

### 1. Create a virtual environment

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

On the Linux production host, install the WSGI server as well:

```bash
pip install -r requirements-production.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

### 2. Configure the secret

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Put the generated value into `.env` as `SECRET_KEY=...`. Do not commit `.env`, paste the key into an issue, or reuse it in another application. The app fails at startup if the key is missing or shorter than 32 characters.

For Windows PowerShell, copy the template with:

```powershell
Copy-Item .env.example .env
```

### 3. Create the first account

```bash
flask --app flask_server create-user
```

Choose a username of 3–32 lowercase letters, digits, dots, underscores or hyphens. Passwords must be 12–72 UTF-8 bytes. There is intentionally no web-based registration endpoint. Use `flask --app flask_server reset-password` to replace an existing account password; this also clears that account's login lockout.

### 4. Run locally (development only)

```bash
flask --app flask_server run --host 127.0.0.1 --port 5000
```

Open `http://127.0.0.1:5000`. The `app.run()` block is also bound to loopback, never `0.0.0.0`.

## Automated Debian / Ubuntu deployment

The included `host_onion_service.sh` installs and configures the production deployment on a fresh Debian or Ubuntu host using systemd. It supports `amd64` and `arm64` and must be run from the project root:

```bash
chmod 0755 host_onion_service.sh
sudo ./host_onion_service.sh
```

The installer:

- Adds the Tor Project APT repository using the repository signing key after checking its published fingerprint, then installs Tor and the Python build/runtime dependencies.
- Creates a dedicated unprivileged `flask-onion-vault` account.
- Installs the application under `/opt/flask-onion-vault`, creates a virtual environment and installs `requirements-production.txt` (including Gunicorn).
- Creates a strong `SECRET_KEY` and a root-only environment file at `/etc/flask-onion-vault/flask-onion-vault.env`.
- Stores the SQLite database and uploads under `/var/lib/flask-onion-vault/`, outside the application web root.
- Adds a clearly marked, repeatable Onion Service block to `/etc/tor/torrc`, first making a timestamped backup. Existing unrelated Tor configuration is preserved.
- Installs a hardened Gunicorn systemd unit, enables both services at boot and binds Gunicorn only to `127.0.0.1:5000`.
- Waits for Tor to create the v3 hostname, prints it and stores the public address in `/etc/flask-onion-vault/ONION_ADDRESS.txt`.
- Offers to create the first application account interactively when the installer is run in a terminal.

The script intentionally does **not** open any public firewall ports. Tor forwards the onion virtual port 80 to the loopback-only Gunicorn listener. It does not install a firewall, configure unattended OS upgrades, scan uploaded files for malware, or independently audit the host. Review the script before running it as root. It is designed to be re-runnable: the existing application secret and Tor Onion Service keys are preserved.

After deployment, useful commands are:

```bash
sudo systemctl status flask-onion-vault
sudo systemctl status tor@default
sudo journalctl -u flask-onion-vault -f
sudo journalctl -u tor@default -f
sudo cat /etc/flask-onion-vault/ONION_ADDRESS.txt
```

If the installer was run non-interactively, or you skipped account creation, create the first account with:

```bash
sudo bash -c 'set -a; source /etc/flask-onion-vault/flask-onion-vault.env; set +a; cd /opt/flask-onion-vault; exec runuser -u flask-onion-vault -- env SECRET_KEY="$SECRET_KEY" DATABASE_PATH="$DATABASE_PATH" UPLOAD_FOLDER="$UPLOAD_FOLDER" /opt/flask-onion-vault/.venv/bin/flask --app flask_server create-user'
```

The Tor private keys are stored in `/var/lib/tor/flask-onion-vault/`. Protect and back up this directory securely. Anyone who obtains the private keys can impersonate the Onion Service. Do not copy the directory into Git or share it.

### Manual deployment

Do not expose the Flask development server to the network. If you do not use the installer, run Gunicorn as a dedicated unprivileged service account and bind only to loopback:

```bash
umask 077
gunicorn --workers 2 --bind 127.0.0.1:5000 --umask 0077 flask_server:app
```

Example Tor `torrc` entries:

```text
HiddenServiceDir /var/lib/tor/onion-vault/
HiddenServicePort 80 127.0.0.1:5000
```

Restart Tor after changing `torrc`. The onion hostname is stored in the `hostname` file inside `HiddenServiceDir`. Protect that directory and its private keys; anyone who obtains those keys can impersonate the service. The Tor Project also documents Unix-socket forwarding as a way to reduce local-network exposure.

The browser-facing origin of a normal Onion Service is commonly `http://…onion`, even though Tor encrypts the onion connection. For that deployment, leave `SESSION_COOKIE_SECURE=false`; setting the cookie's `Secure` attribute on an HTTP origin prevents the browser from sending it. Set `SESSION_COOKIE_SECURE=true` and `ENABLE_HSTS=true` only if the browser-facing connection is actually HTTPS. Do not blindly enable HSTS for an HTTP onion origin.

Recommended deployment controls:

- Run the app and Tor under separate, unprivileged service accounts where practical. Install `requirements-production.txt` on the Linux deployment host to add Gunicorn.
- Keep `HiddenServiceDir`, `.env`, `instance/`, database files and uploads readable only by the accounts that need them. The app creates private data directories on POSIX systems, but verify ownership and permissions after deployment.
- Do not mount `instance/` or the upload directory as a web-server document root.
- Permit inbound traffic only as required by Tor; keep Gunicorn bound to `127.0.0.1` and do not publish port 5000.
- Keep OS packages, Python and dependencies patched. Back up the database and uploads securely, and protect backups to the same standard as the live data.
- Use encrypted storage and monitor disk capacity. This starter has a 1 GiB total upload quota and a 5,000-file cap, but no malware scanner, file deletion interface or automated backup system. Notes are capped at the latest 1,000 records.
- Consider Tor Onion Service client authorization if the service itself should be reachable only by known clients. The application login remains a separate control.

## Security design and limitations

| Area | Implemented control | Remaining consideration |
|---|---|---|
| Secrets | Strong external `SECRET_KEY`; `.env` ignored by Git | Keep secrets out of logs, backups shared with others and repository history. Rotate the key if exposed; doing so invalidates existing sessions. |
| Authentication | bcrypt hashes, no public signup, CLI account creation, generic login error, username-based temporary lockout | Lockout is per username and can be abused to deny a targeted account access. Tor forwards connections from the local Tor daemon, so Flask does not see each visitor's real client IP; do not treat `request.remote_addr` as a per-client identifier or trust arbitrary `X-Forwarded-For` headers. Add carefully designed edge-level throttling if needed. |
| Sessions | HTTP-only, SameSite=Strict, 30-minute lifetime, session cleared on login/logout | Flask's default session is signed client-side, not server-side encrypted storage. Do not put secrets in it; a stolen cookie can be replayed until expiry or `SECRET_KEY` rotation. `Secure` must match the actual browser-facing transport. |
| CSRF | Flask-WTF global protection on POST/PUT/PATCH/DELETE | Keep CSRF enabled and do not cache authenticated pages. |
| SQL | Parameterized statements | Continue using placeholders for every value; never concatenate request data into SQL. |
| XSS | Jinja autoescaping; no `render_template_string` with user input; no inline CSS/JS | Do not add `|safe`, `Markup`, or inline script/style without a reviewed CSP change. |
| Uploads | Authentication, extension allowlist, 16 MiB per-file cap, 1 GiB total quota, 5,000-file cap, random storage names, outside-webroot storage, attachment-only downloads, `nosniff` | File signatures are not inspected and files are not malware-scanned. Treat downloads as untrusted. Add scanning and stricter content validation if the user base expands. |
| Headers | CSP, `nosniff`, frame denial, no referrer, restrictive permissions policy, `no-store` | Review CSP before adding external assets, inline code, embeds or APIs. |
| Network | Loopback binding; Gunicorn for production | OS firewall, Tor configuration, systemd sandboxing and host hardening remain operator responsibilities. |

The upload allowlist can be adjusted in `ALLOWED_EXTENSIONS` near the top of `flask_server.py`. Do not add HTML, SVG, JavaScript or other active browser content unless you deliberately isolate it on a separate origin and review the consequences.

## Tests

```bash
pytest -q
```

Tests cover login protection, security headers, persisted notes and HTML escaping, authenticated file upload/download, active-content extension rejection, CSRF enforcement and migration from the original `users.password` database schema.