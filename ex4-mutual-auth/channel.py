class Channel:
    """Plaintext command channel — no encryption. Compare to Ex5's SecureChannel,
    which wraps this same send_command() flow in AES-GCM encrypt/decrypt calls."""

    def __init__(self, reader, badge):
        self._reader = reader
        self._badge = badge

    def send_command(self, command: str) -> str:
        print(f"[READER] Sending command: {command}")
        response = self._badge.handle_command(command)
        print(f"[BADGE]   Sending response: {response}")
        return response
