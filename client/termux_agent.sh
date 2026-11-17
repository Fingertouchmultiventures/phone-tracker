#!/data/data/com.termux/files/usr/bin/bash
# Phone-side agent for the Phone Tracker server (runs inside Termux on Android).
# Sends location every few minutes, picks up commands (locate, alarm, message).
#
# One-time setup in Termux:
#   pkg install termux-api jq curl
#   (also install the "Termux:API" and "Termux:Boot" apps from F-Droid)
#   Fill in SERVER and TOKEN below, then:  bash termux_agent.sh
# For auto-start after reboot, copy this file to ~/.termux/boot/ (see README).

SERVER="https://YOUR-APP.onrender.com"
TOKEN="PASTE_DEVICE_TOKEN_HERE"
INTERVAL=300

termux-wake-lock

post() {  # post <path> [curl args...]
  local path="$1"; shift
  curl -s -m 40 -H "Authorization: Bearer $TOKEN" "$@" "$SERVER$path"
}

ack() {   # ack <id> <done|unsupported> <result>
  post "/api/commands/$1/ack" -d "status=$2" -d "result=$3" >/dev/null
}

get_location() {
  local loc
  loc=$(timeout 45 termux-location -p gps -r once 2>/dev/null)
  if [ -z "$loc" ] || [ "$(echo "$loc" | jq -r '.latitude // empty')" = "" ]; then
    loc=$(timeout 30 termux-location -p network -r once 2>/dev/null)
  fi
  echo "$loc"
}

run_commands() {   # reads the server JSON reply on $1
  local reply="$1"
  echo "$reply" | jq -c '.commands[]?' | while read -r c; do
    id=$(echo "$c" | jq -r '.id'); type=$(echo "$c" | jq -r '.type'); payload=$(echo "$c" | jq -r '.payload // ""')
    case "$type" in
      locate) ack "$id" done "will ping again now"; touch /tmp/.tracker_ping_now ;;
      message)
        termux-notification --id 9001 --title "Lost phone" --content "$payload" --priority max
        termux-toast "$payload"; ack "$id" done "shown" ;;
      alarm)
        termux-volume music 15 2>/dev/null; termux-volume alarm 7 2>/dev/null
        for i in 1 2 3 4 5 6; do termux-vibrate -d 800 -f; termux-tts-speak "This phone is lost. Please return it."; sleep 1; done
        ack "$id" done "alarm played" ;;
      lock)
        # Termux cannot lock the screen without root/device-admin. Use Find Hub for a real lock.
        ack "$id" unsupported "use Find Hub / Samsung Find to lock" ;;
      *) ack "$id" unsupported "unknown" ;;
    esac
  done
}

while true; do
  loc=$(get_location)
  lat=$(echo "$loc" | jq -r '.latitude // empty'); lon=$(echo "$loc" | jq -r '.longitude // empty')
  acc=$(echo "$loc" | jq -r '.accuracy // empty')
  bat=$(termux-battery-status 2>/dev/null)
  pct=$(echo "$bat" | jq -r '.percentage // empty'); chg=$(echo "$bat" | jq -r '.status // empty')
  ssid=$(termux-wifi-connectioninfo 2>/dev/null | jq -r '.ssid // empty')
  net="wifi:${ssid:-none}"

  reply=$(post /api/ping -d "lat=$lat" -d "lon=$lon" -d "acc=$acc" -d "battery=$pct" -d "charging=$chg" -d "network=$net")
  if [ -n "$reply" ] && [ "$(echo "$reply" | jq -r '.ok // empty')" = "true" ]; then
    INTERVAL=$(echo "$reply" | jq -r '.interval // 300')
    run_commands "$reply"
  fi

  if [ -f /tmp/.tracker_ping_now ]; then rm -f /tmp/.tracker_ping_now; continue; fi
  sleep "$INTERVAL"
done
