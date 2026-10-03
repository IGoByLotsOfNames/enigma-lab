# Path: enigma_demo/__main__.py
"""Start the local browser interface without opening a browser by default."""

import argparse
import sys
import webbrowser

from .server import create_server


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Enigma simulator and complete search demo.")
    parser.add_argument("--port", type=int, default=0, help="local port; 0 selects a free port")
    parser.add_argument(
        "--open-browser", action="store_true", help="also open the local page in your browser"
    )
    args = parser.parse_args(argv)
    try:
        server = create_server(args.port)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(server.url, flush=True)
    try:
        if args.open_browser:
            webbrowser.open(server.url, new=2)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stopped = server.close()
    if not stopped:
        print(
            "Search cancellation is pending; the worker did not stop within the shutdown wait.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
