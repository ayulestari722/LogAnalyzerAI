"""Entry point for LogAnalyzerAI."""

from __future__ import annotations

import sys


def main() -> int:
    """Main entry point — delegates to CLI."""
    from src.cli import cli
    try:
        cli(obj={})
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except KeyboardInterrupt:
        print("\n⚠ Interrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"✗ Fatal error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
