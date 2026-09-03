"""Luna command-result footer support."""

import io
import sys
from contextlib import redirect_stdout


class _Tee:
    def __init__(self, visible, captured):
        self.visible = visible
        self.captured = captured

    def write(self, value):
        self.visible.write(value)
        self.captured.write(value)
        return len(value)

    def flush(self):
        self.visible.flush()


def invoke_with_result(handler, args, success_footer: str, failure_footer: str):
    """Invoke a command while preserving live output and append a result line."""
    visible = sys.stdout
    captured = io.StringIO()
    try:
        with redirect_stdout(_Tee(visible, captured)):
            handler(args)
    except Exception as error:
        print(f"  Error: {error}", file=visible)
        print(failure_footer, file=visible)
        return False

    output = captured.getvalue().lower()
    failure_markers = (
        "  error:", "unknown command", "unknown ", "syntax error",
        "command aborted", "not implemented yet", "login failed",
        "operation failed", "clone failed", "usage:",
    )
    failed = any(marker in output for marker in failure_markers)
    print(failure_footer if failed else success_footer, file=visible)
    return not failed
