#!/usr/bin/env python3
import signal
import os
import subprocess
import sys
import time


APP_MODE = os.environ.get("APP_MODE", "both").lower()

COMMANDS_BY_MODE = {
    "safe": [[sys.executable, "server.py"]],
    "vulnerable": [[sys.executable, "vulnerable_server.py"]],
    "both": [[sys.executable, "server.py"], [sys.executable, "vulnerable_server.py"]],
}


def main():
    commands = COMMANDS_BY_MODE.get(APP_MODE)
    if not commands:
        print("APP_MODE must be one of: safe, vulnerable, both", file=sys.stderr)
        sys.exit(2)

    processes = [subprocess.Popen(command) for command in commands]

    def stop_all(signum, frame):
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop_all)
    signal.signal(signal.SIGINT, stop_all)

    while True:
        for process in processes:
            if process.poll() is not None:
                stop_all(None, None)
        time.sleep(1)


if __name__ == "__main__":
    main()
