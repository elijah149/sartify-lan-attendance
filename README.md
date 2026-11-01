# Sartify Attendance

LAN-only staff attendance system. Admins register users, staff sign in and out
from the office network, and admins review daily and monthly reports.

## Features
- Admin-managed accounts (no public sign-up)
- Access limited to the office network
- One account per device, resettable by admin
- One sign-in and one sign-out per user per day
- Monthly report with CSV export
- Responsive interface (phone, tablet, desktop)

## Run
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python create_admin.py
    ./start.sh

## Stack
FastAPI, SQLite, Jinja2, Inter font
