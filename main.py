import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import telebot
import threading
from app import app

total_money = 0
Good = 0
Bad = 0

# Replace 'YOUR_TELEGRAM_BOT_TOKEN' with your actual bot token
bot_token = '6354971723:AAHMu3CEZaq3dWaSriDKaA3AO1jcaRqPq40'
bot = telebot.TeleBot(bot_token)

# Global flags
running = False
notify = False

def process_account(email, password, chat_id):
    headers = {
        'authority': 'faucetearner.org',
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'ar-YE,ar;q=0.9,en-YE;q=0.8,en-US;q=0.7,en;q=0.6',
        'content-type': 'application/json',
        'origin': 'https://faucetearner.org',
        'referer': 'https://faucetearner.org/login.php',
        'sec-ch-ua': '"Not)A;Brand";v="24", "Chromium";v="116"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }

    params = {
        'act': 'login',
    }

    json_data = {
        'email': email,
        'password': password,
    }

    response = requests.post('https://faucetearner.org/api.php', params=params, headers=headers, json=json_data)

    if "Login successful" in response.text:
        Mahos = response.cookies.get_dict()
        bot.send_message(chat_id, f'✅ Login successful for {email}')
        Money(Mahos, chat_id)
    elif "wrong username or password" in response.text:
        bot.send_message(chat_id, f'❌ Login failed for {email}: Wrong username or password')
    else:
        bot.send_message(chat_id, f'⚠️ Error for {email}')

def Money(cookies, chat_id):
    global total_money, Bad, Good, running
    while running:
        time.sleep(5)
        headers = {
            'authority': 'faucetearner.org',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'accept-language': 'ar-YE,ar;q=0.9,en-YE;q=0.8,en-US;q=0.7,en;q=0.6',
            'origin': 'https://faucetearner.org',
            'referer': 'https://faucetearner.org/faucet.php',
            'sec-ch-ua': '"Not)A;Brand";v="24", "Chromium";v="116"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        params = {
            'act': 'faucet',
        }

        json_data = {}

        rr = requests.post('https://faucetearner.org/api.php', params=params, cookies=cookies, headers=headers).text

        if 'Congratulations on receiving' in rr:
            Good += 1
            json_data = json.loads(rr)
            message = json_data["message"]
            start_index = message.find(">") + 1
            end_index = message.find(" ", start_index)
            balance = message[start_index:end_index]
            total_money += float(balance)
            bot.send_message(chat_id, f"🎉 Received {balance} XRP. Total: {total_money:.2f} XRP")
        elif 'You have already claimed, please wait for the next wave!' in rr:
            Bad += 1
            # bot.send_message(chat_id, f'{E}Bad Claim with this account.')
        else:
            bot.send_message(chat_id, f'⚠️ Error')

def run_accounts(emails, passwords, chat_id):
    global running
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_account, email, password, chat_id) for email, password in zip(emails, passwords)]
        for future in as_completed(futures):
            pass  # Handle results if needed

def start_process(chat_id):
    global running, notify
    running = True
    notify = True
    # List of emails and passwords
    emails = ['imadser', 'imadser001']
    passwords = ['imad2468', 'imad2468']
    bot.send_message(chat_id, "🚀 Starting the process...")
    threading.Thread(target=run_accounts, args=(emails, passwords, chat_id)).start()
    threading.Thread(target=send_notifications, args=(chat_id,)).start()

def stop_process(chat_id):
    global running, notify
    running = False
    notify = False
    bot.send_message(chat_id, "🛑 Stopping the process...")

def send_notifications(chat_id):
    while notify:
        bot.send_message(chat_id, "🔄 The script is still running...")
        time.sleep(60)  # Send notification every 60 seconds

@bot.message_handler(commands=['start'])
def start_message(message):
    bot.send_message(message.chat.id, "👋 Welcome to the bot! Send /run to start the process. Send /stop to stop the process.")

@bot.message_handler(commands=['run'])
def run_message(message):
    bot.send_message(message.chat.id, "⏳ Process will start shortly...")
    threading.Thread(target=start_process, args=(message.chat.id,)).start()

@bot.message_handler(commands=['stop'])
def stop_message(message):
    stop_process(message.chat.id)
app()
if __name__ == "__main__":
    try:
        bot.polling()
    except Exception as e:
     print(f"Error occurred: ")
