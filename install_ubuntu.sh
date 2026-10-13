#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "شغّل السكريبت هكذا: sudo bash install_ubuntu.sh"
  exit 1
fi

APP_DIR="/opt/13x1-hosting"
SERVICE_NAME="13x1-hosting"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip nginx
id -u 13x1host >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin 13x1host
mkdir -p "$APP_DIR"
cp "$SOURCE_DIR/app.py" "$SOURCE_DIR/index.html" "$SOURCE_DIR/login.html" "$SOURCE_DIR/admin_panel.html" "$SOURCE_DIR/requirements.txt" "$SOURCE_DIR/README_AR.md" "$APP_DIR/"
mkdir -p "$APP_DIR/USERS"
[[ -f "$APP_DIR/users.json" ]] || printf '{}\n' > "$APP_DIR/users.json"
[[ -f "$APP_DIR/remember_tokens.json" ]] || printf '{}\n' > "$APP_DIR/remember_tokens.json"
chown -R 13x1host:13x1host "$APP_DIR"
chmod 750 "$APP_DIR"
chmod 640 "$APP_DIR/users.json" "$APP_DIR/remember_tokens.json"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=13X1 Hosting Dashboard
After=network.target

[Service]
Type=simple
User=13x1host
Group=13x1host
WorkingDirectory=${APP_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=SERVER_PORT=21910
ExecStart=${APP_DIR}/.venv/bin/gunicorn --workers 1 --bind 127.0.0.1:21910 --timeout 120 app:app
Restart=always
RestartSec=3
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo
 echo "تم تثبيت 13X1 Hosting وتشغيل الخدمة."
 echo "الحالة: systemctl status ${SERVICE_NAME}"
 echo "السجل: journalctl -u ${SERVICE_NAME} -f"
 echo "اختبار محلي: curl -I http://127.0.0.1:21910/login"
 echo "الخطوة التالية: اربط Nginx والدومين، ثم فعّل HTTPS باستعمال Certbot."
