import sys
import subprocess


def main():
    """
    Guppy ICS launcher.

    - If arguments are provided, forward directly to the CLI (no menu).
    - If no arguments are provided, show an interactive menu.
    """

    # Skip menu if arguments are provided
    if len(sys.argv) > 1:
        _start_cli(sys.argv[1:])
        return

    print()
    print("Guppy ICS")
    print("==========")
    print("1) Browser (Web UI)")
    print("2) Command Line Interface (CLI)")
    print("q) Quit")
    print()

    choice = input("Select mode: ").strip().lower()

    if choice == "1":
        _start_browser()
    elif choice == "2":
        _start_cli([])
    elif choice in ("q", "quit", "exit"):
        sys.exit(0)
    else:
        print("Invalid selection.")
        sys.exit(1)


def _start_browser():
    print("\nStarting Guppy ICS Browser UI...\n")
    print("Listening on http://127.0.0.1:8000")
    print("Press Ctrl-C to stop\n")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "guppy_ics.web.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        check=False,
    )


def _start_cli(args):
    from guppy_ics.cli.guppy import main as cli_main

    print("\nStarting Guppy ICS CLI...\n")

    # If launched from menu with no args, show help
    if not args:
        args = ["--help"]

    cli_main(args)


