"""Module 5b - Action module. Runs only after the user confirms in the dashboard."""
import os
import signal

SIGNALS = {"stop": signal.SIGSTOP, "cont": signal.SIGCONT, "term": signal.SIGTERM}
ACTIONS = set(SIGNALS) | {"renice"}


def perform(pid, action, value, protected):
    """Returns (ok, message). `protected` is a set of PIDs that must never be touched."""
    if action not in ACTIONS:
        return False, f"unknown action {action!r}"
    if not isinstance(pid, int) or pid <= 1 or pid in protected:
        return False, f"PID {pid} is protected"
    try:
        if action == "renice":
            nice = int(value)
            if not -20 <= nice <= 19:
                return False, "nice value must be between -20 and 19"
            os.setpriority(os.PRIO_PROCESS, pid, nice)   # setpriority(2)
            return True, f"PID {pid} reniced to {nice}"
        os.kill(pid, SIGNALS[action])                    # kill(2)
        return True, f"Sent {SIGNALS[action].name} to PID {pid}"
    except ProcessLookupError:
        return False, f"PID {pid} no longer exists"
    except PermissionError:
        hint = " (raising priority needs root)" if action == "renice" else " (process belongs to another user; run as root)"
        return False, f"Permission denied for PID {pid}{hint}"
    except (ValueError, TypeError):
        return False, "invalid value"
