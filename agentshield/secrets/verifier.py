"""Integration helper that verifies a delivered file without printing it."""

import hashlib
import os
import time
from pathlib import Path


def main() -> None:
    path = Path(os.environ.get("AGENTSHIELD_SECRET_PATH", "/run/agentshield/secret"))
    expected = os.environ["AGENTSHIELD_EXPECTED_SHA256"].strip()
    deadline = time.monotonic() + float(os.environ.get("AGENTSHIELD_VERIFY_TIMEOUT", "90"))
    while time.monotonic() < deadline:
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected:
            print(f"verified generation delivery sha256={expected}")
            return
        time.sleep(0.5)
    raise RuntimeError("delivered secret did not match expected fingerprint")


if __name__ == "__main__":
    main()
