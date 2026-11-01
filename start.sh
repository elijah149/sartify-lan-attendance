#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
source venv/bin/activate

# Secret key ya kudumu (watumiaji hawatolewi kila unapowasha upya server)
[ -f .secret_key ] || python -c 'import secrets;print(secrets.token_hex(32))' > .secret_key
chmod 600 .secret_key
export SECRET_KEY="$(cat .secret_key)"

# IP ya LAN inapatikana yenyewe; unaweza kuiweka mwenyewe: HOST_IP=192.168.1.16 ./start.sh
PORT="${PORT:-8000}"
IP="${HOST_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')}"
if [ -z "$IP" ]; then
  echo "Hakuna mtandao wa LAN uliogunduliwa. Unganisha Wi-Fi kisha jaribu tena."
  exit 1
fi

# Mtandao wa ofisi unaoruhusiwa (kawaida /24 ya IP yako)
export ALLOWED_NETWORKS="${ALLOWED_NETWORKS:-127.0.0.1/32,${IP%.*}.0/24}"

echo "Server: http://$IP:$PORT"
echo "Mitandao inayoruhusiwa: $ALLOWED_NETWORKS"
echo "Bonyeza Ctrl+C kuzima."

# Fungua browser baada ya sekunde 2
( sleep 2 && xdg-open "http://$IP:$PORT" >/dev/null 2>&1 ) &

exec uvicorn main:app --host "$IP" --port "$PORT"
