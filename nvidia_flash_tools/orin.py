#!/usr/bin/env python3
"""Guided Orin reference-kit installer. Not tested on physical devices."""
import argparse
from pathlib import Path
from nvidia_flash_tools import thor
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('check', 'prepare', 'install'), default='install')
    parser.add_argument('--board', required=True, choices=('orin', 'orin-nx'),
                        help='orin = P3701-0000/P3737-0000; orin-nx = P3767-0000/P3768-0000')
    parser.add_argument('--bundle-pin')
    args = parser.parse_args(argv)
    return thor.main(([args.action, '--board', args.board] +
                      (['--bundle-pin', args.bundle_pin] if args.bundle_pin else [])))


if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, EOFError) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
