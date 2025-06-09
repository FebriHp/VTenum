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
```bash
docker build -t vtenum .
```
```bash
docker run --rm vtenum
```
### Without Docker
```bash
pip install -r requirements.txt
```
```bash
python main.py
```
## 💻 Usage
Start your Telegram bot by clicking Start or sending the /start command. After that, input the domain you wish to scan

## 📌 Notes

Edit your TELEGRAM_TOKEN and VT_API_KEY in main.py.
Make sure to replace OWNER_ID with your Telegram ID.
