#!/usr/bin/env python3
"""Generate a password hash for use in users.json.
Usage:
  python -m webapp.hash_password              # prompt for password
  python -m webapp.hash_password mypassword     # hash 'mypassword'
  echo -n mypassword | python -m webapp.hash_password -  # read from stdin
"""
import getpass
import os
import sys

# Allow running as python -m webapp.hash_password from project root
_webapp_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_webapp_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from werkzeug.security import generate_password_hash


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-':
            password = sys.stdin.read().strip()
        else:
            password = sys.argv[1]
    else:
        password = getpass.getpass('Password: ')
        if not password:
            print('Empty password.', file=sys.stderr)
            sys.exit(1)
    if not password:
        print('Empty password.', file=sys.stderr)
        sys.exit(1)
    h = generate_password_hash(password, method='pbkdf2:sha256')
    print(h)


if __name__ == '__main__':
    main()
