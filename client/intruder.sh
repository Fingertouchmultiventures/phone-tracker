#!/data/data/com.termux/files/usr/bin/bash
# Take a front-camera photo and upload it to the tracker server.
# Trigger this from Tasker or MacroDroid when a wrong PIN/pattern is entered
# (event: "Failed Unlock Attempt" / "Device Admin: Login Failed").

SERVER="https://YOUR-APP.onrender.com"
TOKEN="PASTE_DEVICE_TOKEN_HERE"
PHOTO="$HOME/intruder_$(date +%s).jpg"

termux-camera-photo -c 1 "$PHOTO"
loc=$(timeout 20 termux-location -p network -r last 2>/dev/null)
lat=$(echo "$loc" | jq -r '.latitude // empty'); lon=$(echo "$loc" | jq -r '.longitude // empty')

curl -s -m 60 -H "Authorization: Bearer $TOKEN" \
  -F "photo=@$PHOTO" -F "lat=$lat" -F "lon=$lon" -F "note=failed unlock attempt" \
  "$SERVER/api/intruder" >/dev/null && rm -f "$PHOTO"
