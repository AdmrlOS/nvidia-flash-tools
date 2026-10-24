#!/usr/bin/env python3
"""Compatibility entrypoint; implementation lives in nvidia_flash_tools."""
import subprocess
import sys
from nvidia_flash_tools.orin import main

if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, EOFError) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
