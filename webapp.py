"""Web app launcher for nginx-upstream deployments.

Behavior:
- Defaults app upstream bind to 127.0.0.1:5000 for nginx proxying.
- In production on Linux, optionally validates/reloads nginx first.
"""

from __future__ import annotations

import os
import platform
import subprocess


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

    # For nginx topology: app upstream local-only unless explicitly overridden.
    if not os.environ.get("UPSTREAM_HOST", "").strip():
        os.environ["UPSTREAM_HOST"] = "127.0.0.1"

    if not os.environ.get("PORT", "").strip():
        os.environ["PORT"] = "5000"


def _maybe_bootstrap_nginx() -> None:
    if platform.system().lower() != "linux":
        return

    if not _env_bool("WEBAPP_AUTO_NGINX", True):
        return

    try:
        test = subprocess.run(
            ["nginx", "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("[webapp] nginx binary not found; skipping nginx bootstrap.")
        return

    if test.returncode != 0:
        print("[webapp] nginx config test failed. External 80/443 may be unavailable.")
        if test.stderr:
            print(test.stderr.strip())
        return

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
            return

    start_result = subprocess.run(["systemctl", "start", "nginx"], check=False)
    if start_result.returncode == 0:
        print("[webapp] nginx started.")
        return

    fallback = subprocess.run(["nginx"], check=False)
    if fallback.returncode == 0:
        print("[webapp] nginx started (direct binary fallback).")
    else:
        print("[webapp] unable to start nginx automatically.")


if __name__ == "__main__":
    _prepare_defaults()
    _maybe_bootstrap_nginx()

    from run import main

    main()
