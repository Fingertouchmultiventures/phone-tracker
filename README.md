# Phone Tracker: setup guide

A private anti-theft server for your own phones (Redmi 13 and Samsung).
The phones report in whenever they have any connection. You watch them on a
dashboard and queue commands.

## What it can and cannot do

| Works | Does not work |
|---|---|
| Location pings over mobile data or Wi-Fi (including in-flight Wi-Fi) | Anything while the phone is fully offline or powered off |
| Intruder photo plus location uploads | Locking or wiping the phone (needs Find Hub / Samsung Find) |
| Sound alarm and on-screen message commands | A PWA doing background tracking (not possible in browsers) |
| Lost mode (phone reports every 60 s instead of 5 min) | Seeing which cell tower the phone uses (only your carrier can) |

**Keep Find Hub, Samsung Find and Xiaomi Cloud turned on.** They provide the real lock and erase. This server is an extra layer.

## 1. Deploy the server (Render)

1. Put this folder in a GitHub repo.
2. In Render: New, then Blueprint, pick the repo (it reads `render.yaml`).
3. When asked, set **ADMIN_PASSWORD** to a long password (12+ characters).
4. Open `https://<your-app>.onrender.com`, sign in, and **Add a device** for each phone.
   The **device token is shown once**. Copy it.

Free-tier note: the free Render plan has no persistent disk, so the database and
photos would be wiped on every restart. Use the paid disk in `render.yaml`, or
change `DATA_DIR` to a persistent location on whatever host you use.

Run locally to try it: `ADMIN_PASSWORD=test python app.py`, then open http://localhost:5000

## 2. Phone agent (Termux)

On each phone:
1. Install **F-Droid**, then from it install **Termux**, **Termux:API** and **Termux:Boot**.
2. In Termux: `pkg install termux-api jq curl`
3. Copy `client/termux_agent.sh` and `client/intruder.sh` to the phone. Edit both and set
   `SERVER` and `TOKEN` (that phone's own token).
4. Grant Termux:API the **Location (all the time)** and **Camera** permissions in Android settings.
5. Test: `bash termux_agent.sh`. The phone should appear as "last seen" on the dashboard.
6. Auto-start after reboot: `mkdir -p ~/.termux/boot && cp termux_agent.sh ~/.termux/boot/start-tracker.sh`

**Redmi 13 (HyperOS/MIUI):** Settings, Apps, Termux, set Autostart on and Battery saver to
"No restrictions". Do the same for Termux:API and Termux:Boot, and lock Termux in the
recent-apps screen. Xiaomi kills background apps otherwise.

**Samsung:** Settings, Battery, Background usage limits, add Termux to "Never sleeping apps".

## 3. Intruder photos

Use Tasker or MacroDroid to run `intruder.sh` when a wrong PIN or pattern is entered
(event "Failed Unlock Attempt" or similar). The photo and location then appear
on the dashboard. Android only allows this event on some versions, so test it.

## 4. Using it when the phone is stolen

1. Open the dashboard, pick the phone, press **Turn on lost mode** (faster pings).
2. Press **Locate now**, **Show message** (put a phone number to call) or **Sound alarm**.
3. At the same time use android.com/find or Samsung Find to **Secure device** (lock) and, if it is hopeless, Erase.
4. Report to the police and your carrier with the IMEI (`*#06#`).
   Do not try to recover the phone alone. Give the police the location.

## Security notes

- Device tokens are stored hashed. Lose one and you create a new device.
- The login blocks after 5 wrong passwords per 15 minutes. Use a long password.
- Photos are only served to a signed-in admin.
- A thief who removes Termux or does a factory reset stops the agent. That is why
  Find Hub and Samsung Find remain the main protection.

## API (for Tasker/MacroDroid if you prefer)

Header: `Authorization: Bearer <token>`
- `POST /api/ping` with `lat lon acc battery charging network`
- `GET /api/commands`
- `POST /api/commands/<id>/ack` with `status=done|unsupported result=...`
- `POST /api/intruder` (multipart `photo`, optional `lat lon note`)
