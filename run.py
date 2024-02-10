#!/usr/bin/env python3
"""One-command local demonstration and evidence build. No network or credentials needed."""
import argparse
from pathlib import Path
from mosslight.store import ROOT, initialize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=['demo', 'serve', 'verify', 'package'], default='demo')
    parser.add_argument('--port', type=int, default=8767)
    args = parser.parse_args()
    if args.command == 'serve':
        from mosslight.server import FieldbookServer
        initialize(ROOT / 'var' / 'fieldbook.sqlite', ROOT / 'var' / 'demo-credentials.txt')
        server = FieldbookServer(ROOT / 'var' / 'fieldbook.sqlite', port=args.port)
        print(f'Open {server.origin} (use this exact host).')
        print('Local account passwords: var/demo-credentials.txt. Press Ctrl+C to stop.')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nStopped.')
        finally:
            server.server_close()
        return
    from scripts.evaluate import evaluate
    from scripts.build_docs import build
    from scripts.policy_check import check
    report = evaluate()
    check()
    build(report)
    if args.command == 'demo':
        initialize(ROOT / 'var' / 'fieldbook.sqlite', ROOT / 'var' / 'demo-credentials.txt')
        print('Ready: docs/index.html is the offline evidence exhibit.')
        print('Run python3 run.py serve for the application; local passwords are in var/demo-credentials.txt.')
    elif args.command == 'package':
        from scripts.package_release import package
        print(package())
    else:
        print(f"Verified {report['passed']} checks; policy gates passed; evidence rebuilt.")


if __name__ == '__main__':
    main()
