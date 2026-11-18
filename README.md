# Phone Tracker: setup guide

A private anti-theft server for your own phones (Redmi 13 and Samsung).
Runs on **Vercel**, stores data in **Supabase** (private `tracker` schema).
The phones report in whenever they have any connection. You watch them on a
dashboard and queue commands.

## What it can and cannot do

| Works | Does not work |
|---|---|
| Location pings over mobile data or Wi-Fi (including in-flight Wi-Fi) | Anything while the phone is fully offline or powered off |
| Intruder photo plus location uploads (photos up to 4 MB) | Locking or wiping the phone (needs Find Hub / Samsung Find) |
| Sound alarm and on-screen message commands | A PWA doing background tracking (not possible in browsers) |
| Lost mode (phone reports every 60 s instead of 5 min) | Seeing which cell tower the phone uses (only your carrier can) |

**Keep Find Hub, Samsung Find and Xiaomi Cloud turned on.** They provide the real lock and erase.

## Environment variables (Vercel, Project Settings, Environment Variables)

| Name | Value |
|---|---|
| `DATABASE_URL` | Supabase **transaction pooler** URL, using the `tracker_app` user (not `postgres`) |
| `ADMIN_PASSWORD` | A long password for the dashboard |
| `SECRET_KEY` | Optional, 24+ random characters |
| `TZ_NAME` | Optional, default `Africa/Lagos` |

## Database

Tables live in the `tracker` schema (see `schema.sql`). The app connects as the
`tracker_app` role, which can only access that schema, never your other tables.
Rows older than 60 days are deleted automatically.

## Phone agent (Termux)

1. Install **Termux**, **Termux:API** and **Termux:Boot** from F-Droid (same source for all three).
2. In Termux: `pkg install termux-api jq curl`
3. Allow Termux:API location (all the time) and camera in Android settings.
4. Save the device token: `echo 'TOKEN' > ~/.tracker_token`
5. Put `client/termux_agent.sh` on the phone as `~/tracker.sh`, set `SERVER` to your Vercel address, run `bash ~/tracker.sh`.
6. Auto-start after reboot: `mkdir -p ~/.termux/boot && cp ~/tracker.sh ~/.termux/boot/start-tracker.sh`

**Redmi 13:** Settings, Apps, Termux, Autostart on and Battery saver "No restrictions" (same for Termux:API and Termux:Boot).
**Samsung:** Settings, Battery, Background usage limits, add Termux to "Never sleeping apps".

## When the phone is stolen

1. Dashboard, pick the phone, **Turn on lost mode**.
2. **Locate now**, **Show message** (put a number to call) or **Sound alarm**.
3. Use android.com/find or Samsung Find to **Secure device** (lock) and, if hopeless, Erase.
4. Report to the police and carrier with the IMEI (`*#06#`). Give the police the location; don't confront anyone.

## API

Header: `Authorization: Bearer <token>`
- `POST /api/ping` with `lat lon acc battery charging network`
- `GET /api/commands`
- `POST /api/commands/<id>/ack` with `status=done|unsupported result=...`
- `POST /api/intruder` (multipart `photo`, optional `lat lon note`)
