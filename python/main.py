import atexit
import ctypes
import os
import signal
import sys
import webbrowser
from pathlib import Path

from app import InfernoApp, create_handler
from http.server import ThreadingHTTPServer


def preflight_native_engine_or_exit() -> None:
    lib_path = Path("./build/libinferno.so")
    try:
        ctypes.CDLL(str(lib_path))
    except Exception as exc:
        print(f"[FATAL] Native engine unavailable: {exc}")
        sys.exit(1)


def run_server(host: str = "0.0.0.0", port: int = 8000):
    if not os.path.exists("build/libinferno.so"):
        print("[ERROR] Native Engine (libinferno.so) not found")
        sys.exit(1)

    app_state = InfernoApp()
    item_count, net_potential = app_state.finance_ledger_summary()
    print(f"[✓] FINANCE: Ledger active (${net_potential / 100:.2f} Net Value)")
    server = ThreadingHTTPServer((host, port), create_handler(app_state))
    local_url = f"http://127.0.0.1:{port}"

    print(f"[STARTUP] Server listening on {host}:{port}")

    if os.environ.get("INFERNO_OPEN_BROWSER", "1") == "1":
        try:
            webbrowser.open(local_url)
        except Exception as exc:
            print(f"[WARN] Browser auto-open skipped: {exc}")

    def _shutdown(*_args):
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    atexit.register(app_state.shutdown)

    try:
        print(f"[READY] System listening at http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
        app_state.shutdown()


if __name__ == "__main__":
    boot_banner = [
        "██████████████████████████████████████████████████████████",
        "█         INFERNO SOVEREIGN KERNEL :: SECURE BOOT         █",
        "██████████████████████████████████████████████████████████",
    ]
    for line in boot_banner:
        print(line)
    print("[STARTUP] Initializing Project Inferno")
    preflight_native_engine_or_exit()
    host = os.environ.get("INFERNO_HOST", "0.0.0.0")
    port = int(os.environ.get("INFERNO_PORT", "8000"))
    run_server(host=host, port=port)
