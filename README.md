
# Manus Cookie Validator Telegram Bot

This bot allows you to validate Manus cookie files directly via Telegram. It is designed to be hosted on GitHub Actions with an automatic reset every 6 hours.

## Features
- **Zip Support**: Send a `.zip` file containing multiple `.txt` cookie files.
- **Single File Support**: Send individual `.txt` cookie files.
- **Automatic Validation**: Uses the Manus internal API for fast validation.
- **Results**: Sends back a summary message and a `.zip` file containing all valid cookies, renamed with their plan, credits, and email.

## Setup Instructions

### 1. Create a GitHub Repository
Create a new private repository on GitHub.

### 2. Add Files
Upload the following files to your repository:
- `bot.py`: The main bot script.
- `.github/workflows/bot.yml`: The GitHub Actions workflow file.
- `README.md`: This instruction file.

### 3. Set Up Secrets
To keep your bot token secure, you must add it as a GitHub Secret:
1. Go to your repository on GitHub.
2. Click on **Settings** > **Secrets and variables** > **Actions**.
3. Click **New repository secret**.
4. Name: `TELEGRAM_BOT_TOKEN`
5. Value: `8057083716:AAEOcpVcRARL5Efg-iGIekof0cFU3wKmi1c` (or your latest token).

### 4. Enable Actions
1. Click on the **Actions** tab in your repository.
2. You should see the "Telegram Bot" workflow.
3. If it's not already running, you can trigger it manually by clicking **Run workflow**.

## How it Works on GitHub Actions
The workflow is configured to:
- Run automatically every 6 hours using a cron schedule (`0 */6 * * *`).
- Install the necessary Python dependencies (`python-telegram-bot`, `requests`).
- Start the bot and keep it running.
- GitHub Actions has a default timeout (usually 6 hours for the free tier), so the bot will naturally stop and then be restarted by the next scheduled run.

## Usage
Once the bot is running, simply send it a `.zip` or `.txt` file in Telegram. It will process the cookies and reply with the results.
