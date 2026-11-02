#!/usr/bin/env bash
# macOS / Linux: ./run_local.sh
set -e
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt
mkdir -p instance
if [ ! -f instance/admin_created.flag ]; then
  flask --app wsgi init-db
  flask --app wsgi create-admin --username admin
  touch instance/admin_created.flag
fi
export BASE_BAN_SECONDS=${BASE_BAN_SECONDS:-60}
echo "User portal: http://127.0.0.1:5000/login"
echo "Admin console: http://127.0.0.1:5000/admin/login"
flask --app wsgi run
