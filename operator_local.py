"""Simple local-only operator dashboard launcher."""

import os

# Force local bind for operator access over SSH tunnel only.
os.environ["OPERATOR_HOST"] = "127.0.0.1"
os.environ.setdefault("ALLOW_REMOTE_OPERATOR", "0")

import operator_dashboard as od


if __name__ == "__main__":
    print(
        "Starting operator dashboard on 127.0.0.1:"
        f"{od.OPERATOR_PORT} (local-only)."
    )
    od.ensure_operator_log_file()
    od.load_events_from_file()
    od.app.run(host="127.0.0.1", port=od.OPERATOR_PORT, debug=False)
