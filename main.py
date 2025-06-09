import requests
import time
import re
from telegram import Update, Bot
from telegram.ext import Updater, MessageHandler, Filters, CallbackContext

# Configuration
TELEGRAM_TOKEN = 'TELEBOT_Token'
VT_API_KEY = 'Virustotal_API'
OWNER_ID = Your_Telegram_ID  # Only this Telegram user can use the bot

# Query VirusTotal domain report
def scan_domain(domain):
    url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={VT_API_KEY}&domain={domain}'
    try:
        response = requests.get(url)
        data = response.json()
        undetected = data.get('undetected_urls', [])
        subdomains = data.get('subdomains', [])
        return undetected, subdomains
    except Exception as e:
        return [], []

# Format undetected URLs
def format_urls(urls):
    return '\n'.join([u[0] for u in urls]) if urls else 'No undetected URLs found.'

# Send long messages in chunks (Telegram limit is 4096 characters)
def send_long_message(context: CallbackContext, chat_id: int, message: str):
    max_length = 4096
    for i in range(0, len(message), max_length):
        context.bot.send_message(chat_id=chat_id, text=message[i:i + max_length])

# Handle incoming messages
def handle_message(update: Update, context: CallbackContext):
    user_id = update.effective_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("🚫 Access denied.")
        return

    domain = update.message.text.strip()
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        update.message.reply_text("⚠️ Invalid domain format.")
        return

    update.message.reply_text(f"🔍 Scanning: {domain}")

    undetected, subdomains = scan_domain(domain)
    if undetected:
        msg = f"🌐 Undetected URLs for {domain}:\n{format_urls(undetected)}"
        send_long_message(context, update.effective_chat.id, msg)
    else:
        update.message.reply_text(f"🌐 No undetected URLs for {domain}.")

    for sub in subdomains:
        time.sleep(15)  # Respect VirusTotal rate limit (max 4 req/min)
        undetected_sub, _ = scan_domain(sub)
        if undetected_sub:
            msg = f"🔗 Undetected URLs for subdomain {sub}:\n{format_urls(undetected_sub)}"
            send_long_message(context, update.effective_chat.id, msg)

    update.message.reply_text("✅ Done.")

# Entry point
def main():
    updater = Updater(token=TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))
    print("Bot is running...")
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
