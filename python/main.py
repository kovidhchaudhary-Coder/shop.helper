import atexit
import signal

from app import InfernoApp, create_handler
from http.server import ThreadingHTTPServer


def run_server(host: str = "0.0.0.0", port: int = 8000):
    app_state = InfernoApp()
    server = ThreadingHTTPServer((host, port), create_handler(app_state))

    def _shutdown(*_args):
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    atexit.register(app_state.shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        app_state.shutdown()


if __name__ == "__main__":
    run_server()
