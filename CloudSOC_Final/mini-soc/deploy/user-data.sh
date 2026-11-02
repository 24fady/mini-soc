#!/bin/bash
# Launch Template -> Advanced details -> User data.
# Requirements: Ubuntu 22.04 AMI, IAM instance profile with:
#   - AmazonSSMManagedInstanceCore (optional, for Session Manager)
#   - CloudWatchAgentServerPolicy
#   - read access to SSM parameters under /minisoc/  (ssm:GetParameter + kms:Decrypt)
# SSM SecureString parameters to create first:
#   /minisoc/SECRET_KEY   /minisoc/DATABASE_URL   /minisoc/ADMIN_PASSWORD
set -euxo pipefail

REGION="eu-central-1"                                  # <-- change
REPO_URL="https://github.com/YOUR_TEAM/mini-soc.git"   # <-- change
APP_DIR=/opt/mini-soc

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-venv python3-pip nginx git awscli curl

# ---- application ----
git clone "$REPO_URL" "$APP_DIR"
chown -R ubuntu:ubuntu "$APP_DIR"
sudo -u ubuntu python3 -m venv "$APP_DIR/venv"
sudo -u ubuntu "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
mkdir -p /var/log/mini-soc && chown ubuntu:ubuntu /var/log/mini-soc

# ---- secrets from Parameter Store (nothing hard-coded) ----
get() { aws ssm get-parameter --region "$REGION" --with-decryption --name "/minisoc/$1" --query Parameter.Value --output text; }
cat > /etc/mini-soc.env <<ENV
SECRET_KEY=$(get SECRET_KEY)
DATABASE_URL=$(get DATABASE_URL)
PROXY_HOPS=2
SESSION_COOKIE_SECURE=false
LOG_FILE=/var/log/mini-soc/app.log
MAX_FAILED_ATTEMPTS=5
ATTEMPT_WINDOW_SECONDS=120
BASE_BAN_SECONDS=900
ENV
chmod 600 /etc/mini-soc.env
ADMIN_PASSWORD="$(get ADMIN_PASSWORD)"

# ---- database tables + admin (idempotent) ----
cd "$APP_DIR"
set -a; . /etc/mini-soc.env; set +a
sudo -E -u ubuntu "$APP_DIR/venv/bin/flask" --app wsgi init-db || true
ADMIN_PASSWORD="$ADMIN_PASSWORD" sudo -E -u ubuntu "$APP_DIR/venv/bin/flask" --app wsgi create-admin --username admin || true

# ---- services ----
cp deploy/gunicorn.service /etc/systemd/system/gunicorn.service
cp deploy/nginx.conf /etc/nginx/sites-available/mini-soc
ln -sf /etc/nginx/sites-available/mini-soc /etc/nginx/sites-enabled/mini-soc
rm -f /etc/nginx/sites-enabled/default
systemctl daemon-reload
systemctl enable --now gunicorn
nginx -t && systemctl restart nginx

# ---- CloudWatch agent ----
curl -fsSL -o /tmp/cwagent.deb https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i /tmp/cwagent.deb
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 \
  -c file:"$APP_DIR/deploy/cloudwatch-agent.json" -s
