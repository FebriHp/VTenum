# VTenum - Telegram Bot for VirusTotal Domain Scan

This bot allows you to scan a domain using VirusTotal API and returns:
- Undetected URLs
- Subdomains and their associated undetected URLs

## 🚀 Features

- Handles long output by splitting messages
- Works via Telegram with restricted access to one user (OWNER_ID)
- Can be run using Docker

## 🔧 Requirements

- Python 3.10+
- Telegram Bot Token
- VirusTotal API Key

## 📦 Installation

### Using Docker

docker build -t vtenum .
docker run --rm vtenum

### Without Docker

pip install -r requirements.txt
python main.py

## Notes

Edit your TELEGRAM_TOKEN and VT_API_KEY in main.py.
Make sure to replace OWNER_ID with your Telegram ID.
