from pathlib import Path

_DEFAULT_LOG = Path(__file__).parent / "logs" / "observed_uids.txt"


class Reader:
    ALLOWLIST = [b"A3F29C11", b"B7E10422", b"C1D34F88"]

    def __init__(self, allowlist: list[bytes] = None, log_path: Path = _DEFAULT_LOG):
        self.allowlist = [uid.upper() for uid in (allowlist or self.ALLOWLIST)]
        self.log_path = Path(log_path)

    def present(self, badge) -> bool:
        print(f"[READER] Received UID: {badge.uid.decode()}")
        granted = badge.uid in self.allowlist
        self._log(f"{badge.uid.decode()},{'GRANTED' if granted else 'DENIED'}")
        if granted:
            print("[READER] UID found in allowlist.")
            print("[DOOR]   *** ACCESS GRANTED ***")
        else:
            print("[READER] UID not in allowlist.")
            print("[DOOR]   *** ACCESS DENIED ***")
        return granted

    def _log(self, line: str):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(f"{line}\n")
