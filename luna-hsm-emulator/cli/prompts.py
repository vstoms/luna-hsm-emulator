"""Authentic Luna-style confirmation prompts.

Real Luna shells (lunash and lunacm) never ask "yes/no" before a
destructive operation.  They print a CAUTION block and require the
operator to type the word 'proceed' exactly; any other input aborts
the command.  This module reproduces that ceremony so trainees build
the correct muscle memory.
"""


def confirm_proceed(*warning_lines, force: bool = False) -> bool:
    """Display a Luna-style CAUTION block and require 'proceed' to continue.

    Args:
        *warning_lines: One or more lines describing the destructive action.
        force: When True (e.g. the command was invoked with -force),
               skip the prompt entirely, as on a real Luna.

    Returns:
        True if the operator typed 'proceed', False otherwise.
    """
    if force:
        return True

    lines = [line for line in warning_lines if line] or [
        "Are you sure you wish to continue?"
    ]
    print()
    for index, line in enumerate(lines):
        prefix = "CAUTION:  " if index == 0 else "          "
        print(f"{prefix}{line}")
    print()
    print("          Type 'proceed' to continue, or 'quit'")
    print("          to quit now.")
    try:
        answer = input("          > ")
    except (EOFError, KeyboardInterrupt):
        print()
        answer = ""

    if answer.strip() == "proceed":
        print("Proceeding...")
        return True
    print("Command aborted.")
    return False
