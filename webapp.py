"""Web app launcher with auto routing mode.

Modes:
- auto (default): use nginx-first when nginx is available, otherwise direct bind.
- nginx: require nginx-first topology (nginx on 80/443 -> app on 127.0.0.1:5000).
- direct: run app directly on 0.0.0.0:5000 for external IP access.
"""

from __future__ import annotations

import os
import platform
import subprocess
import shutil


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _prepare_defaults() -> None:
    # Keep startup in production mode by default.
    os.environ.setdefault("FLASK_ENV", "production")
    os.environ.setdefault("FLASK_DEBUG", "0")
    os.environ.setdefault("USE_FLASK_DEV_SERVER", "0")

    if not os.environ.get("PORT", "").strip():
        os.environ["PORT"] = "5000"


def _mode() -> str:
    raw = os.environ.get("WEBAPP_BIND_MODE", "auto").strip().lower()
    if raw in {"auto", "nginx", "direct"}:
        return raw
    return "auto"


def _nginx_available() -> bool:
    return shutil.which("nginx") is not None


def _configure_direct_bind() -> None:
    # External-IP mode: app listens directly on HOST/PORT.
    os.environ.pop("UPSTREAM_HOST", None)
    if not os.environ.get("HOST", "").strip():
        os.environ["HOST"] = "0.0.0.0"


def _configure_nginx_upstream() -> None:
    # Nginx mode: app should stay local-only behind reverse proxy.
    if not os.environ.get("UPSTREAM_HOST", "").strip():
        os.environ["UPSTREAM_HOST"] = "127.0.0.1"


def _maybe_bootstrap_nginx() -> bool:
    if platform.system().lower() != "linux":
        return False

    if not _env_bool("WEBAPP_AUTO_NGINX", True):
        return False

    try:
        test = subprocess.run(
            ["nginx", "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("[webapp] nginx binary not found; cannot bootstrap nginx.")
        return False

    if test.returncode != 0:
        print("[webapp] nginx config test failed. External 80/443 may be unavailable.")
        if test.stderr:
            print(test.stderr.strip())
        return False

    # Try managed service first, then direct reload/start fallback.
    systemctl = subprocess.run(
        ["systemctl", "is-active", "nginx"],
        capture_output=True,
        text=True,
        check=False,
    )
    if systemctl.returncode == 0 and systemctl.stdout.strip() == "active":
        reload_result = subprocess.run(["nginx", "-s", "reload"], check=False)
        if reload_result.returncode == 0:
            print("[webapp] nginx reloaded.")
            return True

    start_result = subprocess.run(["systemctl", "start", "nginx"], check=False)
    if start_result.returncode == 0:
        print("[webapp] nginx started.")
        return True

    fallback = subprocess.run(["nginx"], check=False)
    if fallback.returncode == 0:
        print("[webapp] nginx started (direct binary fallback).")
        return True
    else:
        print("[webapp] unable to start nginx automatically.")
        return False


if __name__ == "__main__":
    _prepare_defaults()

    selected_mode = _mode()
    nginx_present = _nginx_available()

    if selected_mode == "direct":
        _configure_direct_bind()
        print("[webapp] mode=direct -> app will bind to HOST for external IP access.")
    elif selected_mode == "nginx":
        _configure_nginx_upstream()
        if not nginx_present:
            print("[webapp] mode=nginx but nginx is not installed. Falling back to direct bind.")
            _configure_direct_bind()
        else:
            _maybe_bootstrap_nginx()
            print("[webapp] mode=nginx -> app will bind local upstream for nginx.")
    else:
        if nginx_present:
            _configure_nginx_upstream()
            _maybe_bootstrap_nginx()
            print("[webapp] mode=auto -> detected nginx, using nginx upstream mode.")
        else:
            _configure_direct_bind()
            print("[webapp] mode=auto -> nginx missing, using direct bind mode.")

    from run import main

    main()
