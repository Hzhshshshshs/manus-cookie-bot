import os
import json
import time
import glob
import re
import base64
import concurrent.futures
import requests
import zipfile
from datetime import datetime
from telegram import Update, File, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler, CallbackQueryHandler
from collections import Counter

# Global dictionary to store user sorting preferences
USER_SORT_PREFERENCES = {}

# States for conversation handler
SELECTING_SORT_OPTION = 0

# ─── Configuration ───────────────────────────────────────────────────────────
# These will be set via environment variables in GitHub Actions
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
COOKIES_DIR = "./manus_cookies_input"
OUTPUT_DIR = "./manus_cookies_output"
MAX_WORKERS = 20
MAX_RETRIES = 2
REQUEST_TIMEOUT = 15

API_BASE = "https://api.manus.im"
USER_INFO_URL = f"{API_BASE}/user.v1.UserService/UserInfo"
CREDITS_URL = f"{API_BASE}/user.v1.UserService/GetAvailableCredits"

os.makedirs(COOKIES_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Plan name mapping from API membershipVersion values
PLAN_MAP = {
    'free': 'Free',
    'pro': 'Pro',
    'plus': 'Plus',
    'max': 'Max',
    'team': 'Team',
    'casual': 'Casual',
}



def parse_netscape_cookies(file_path):
    """Parse Netscape-format cookie file into a dict of {name: value}."""
    cookies = {}
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) < 7:
                    parts = re.split(r'\s+', line)
                    if len(parts) < 7:
                        continue
                cookies[parts[5]] = parts[6]
    except Exception as e:
        print(f"  Error parsing {file_path}: {e}")
    return cookies


def decode_jwt(token):
    """Decode a JWT token payload (no signature verification)."""
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        pass
    return {}


def call_api(url, headers):
    """Make a single API call and return (status_code, json_or_none)."""
    try:
        r = requests.post(url, headers=headers, json={}, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, None
    except Exception as e:
        return 0, None


def validate_cookie_file(file_path):
    """Validate a single cookie file using direct API calls."""
    filename = os.path.basename(file_path)
    if filename == "test_cookie.txt":
        return None

    cookies = parse_netscape_cookies(file_path)
    session_id = cookies.get('session_id', '')

    if not session_id:
        return {"file": filename, "status": "error", "message": "No session_id cookie"}

    # Pre-extract from JWT as fallback
    jwt_data = decode_jwt(session_id)
    jwt_email = jwt_data.get('email', '')
    jwt_name = jwt_data.get('name', '')

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {session_id}',
        'Origin': 'https://manus.im',
        'Referer': 'https://manus.im/app',
    }

    for attempt in range(MAX_RETRIES):
        try:
            # ── Call both endpoints in parallel using threads ──
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as mini_pool:
                user_future = mini_pool.submit(call_api, USER_INFO_URL, headers)
                credits_future = mini_pool.submit(call_api, CREDITS_URL, headers)
                user_status, user_data = user_future.result()
                credits_status, credits_data = credits_future.result()

            # ── Check auth ──
            if user_status == 401 or credits_status == 401:
                return {"file": filename, "status": "invalid"}

            if user_data is None:
                raise Exception(f"UserInfo failed with status {user_status}")
            if credits_data is None:
                raise Exception(f"GetAvailableCredits failed with status {credits_status}")

            # ── Extract user info ──
            email = user_data.get('email', '') or jwt_email
            name = user_data.get('displayname', '') or user_data.get('nickname', '') or jwt_name

            # ── Plan ──
            membership = user_data.get('membershipVersion', 'free').lower()
            plan = PLAN_MAP.get(membership, membership.capitalize())

            # ── Billing period ──
            billing = 'none'
            if plan != 'Free':
                interval = (
                    user_data.get('membershipInterval', '') or
                    user_data.get('membershipInfo', {}).get('membershipInterval', '')
                )
                billing = interval.lower() if interval else 'unknown'

            # ── Renewal date ──
            renewal_date = ''
            period_end = (
                user_data.get('currentPeriodEnd', '') or
                user_data.get('membershipInfo', {}).get('currentPeriodEnd', '')
            )
            if period_end:
                try:
                    dt = datetime.utcfromtimestamp(int(period_end))
                    renewal_date = dt.strftime('%b %d, %Y')
                except Exception:
                    renewal_date = str(period_end)

            # ── Credits ──
            total_credits = credits_data.get('totalCredits', 0)
            free_credits = credits_data.get('freeCredits', 0)
            periodic_credits = credits_data.get('periodicCredits', 0)
            daily_refresh = credits_data.get('refreshCredits', 0)
            max_refresh = credits_data.get('maxRefreshCredits', 0)
            addon_credits = credits_data.get('addonCredits', 0)

            # Monthly limit
            monthly_limit = 0
            for key in ['proMonthlyCredits', 'casualMonthlyCredits', 'plusMonthlyCredits',
                        'maxMonthlyCredits', 'teamMonthlyCredits', 'monthlyCredits']:
                val = credits_data.get(key, 0)
                if val:
                    monthly_limit = val
                    break

            # Membership tier
            membership_tier = user_data.get('membershipTier', 0)

            total_with_refresh = total_credits

            # ── Save cookie file with descriptive name ──
            safe_email = email if email else 'unknown'
            new_filename = f"[{plan.lower()}][{billing}][{total_with_refresh}][{monthly_limit}][{safe_email}].txt"

            subdir = "Free" if plan == "Free" else "Premium"
            out_subdir = os.path.join(OUTPUT_DIR, subdir)
            os.makedirs(out_subdir, exist_ok=True)

            with open(os.path.join(out_subdir, new_filename), 'w') as f:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as src:
                    f.write(src.read())

            result = {
                "file": filename,
                "status": "valid",
                "email": email,
                "name": name,
                "plan": plan,
                "billing": billing,
                "membership_tier": membership_tier,
                "total_credits": total_credits,
                "daily_refresh_credits": daily_refresh,
                "max_refresh_credits": max_refresh,
                "total_with_refresh": total_with_refresh,
                "free_credits": free_credits,
                "periodic_credits": periodic_credits,
                "monthly_credits_limit": monthly_limit,
                "addon_credits": addon_credits,
                "renewal_date": renewal_date,
                "subscription_status": user_data.get('subscriptionStatus', ''),
                "payment_platform": user_data.get('paymentPlatform', ''),
                "output_file": new_filename
            }

            print(f"  OK: {filename} -> {plan} | {billing} | {total_with_refresh} credits | {email}")
            return result

        except requests.exceptions.Timeout:
            print(f"  Attempt {attempt + 1} timed out for {filename}")
            if attempt == MAX_RETRIES - 1:
                return {"file": filename, "status": "error", "message": "Request timeout"}
        except Exception as e:
            print(f"  Attempt {attempt + 1} failed for {filename}: {e}")
            if attempt == MAX_RETRIES - 1:
                return {"file": filename, "status": "error", "message": str(e)}
            time.sleep(1)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Hi! Send me a .txt cookie file or a .zip archive containing multiple cookie files, "
        "and I'll validate them for you.\n\n"
        "You can also use /sort to change how the results are ordered."
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name

    if file_name.endswith('.txt'):
        await update.message.reply_text(f"Received single cookie file: {file_name}. Validating...")
        try:
            new_file: File = await context.bot.get_file(document.file_id)
            file_path = os.path.join(COOKIES_DIR, file_name)
            await new_file.download_to_drive(file_path)
            await process_cookie_files(update, context, [file_path])
        except Exception as e:
            await update.message.reply_text(f"Error processing file: {e}")

    elif file_name.endswith('.zip'):
        await update.message.reply_text(f"Received zip archive: {file_name}. Extracting and validating...")
        try:
            new_file: File = await context.bot.get_file(document.file_id)
            zip_path = os.path.join(COOKIES_DIR, file_name)
            await new_file.download_to_drive(zip_path)

            extracted_files = []
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member.endswith('.txt'):
                        extracted_path = os.path.join(COOKIES_DIR, os.path.basename(member))
                        with open(extracted_path, "wb") as output_file:
                            with zip_ref.open(member) as input_file:
                                output_file.write(input_file.read())
                        extracted_files.append(extracted_path)
            os.remove(zip_path)  # Clean up the zip file
            await process_cookie_files(update, context, extracted_files)
        except Exception as e:
            await update.message.reply_text(f"Error processing zip file: {e}")

    else:
        await update.message.reply_text(
            "Please send a .txt cookie file or a .zip archive containing .txt cookie files."
        )


async def process_cookie_files(update: Update, context: ContextTypes.DEFAULT_TYPE, file_paths: list):
    # Clear previous results
    for f in glob.glob(os.path.join(OUTPUT_DIR, "**/*"), recursive=True):
        if os.path.isfile(f):
            os.remove(f)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(validate_cookie_file, f): f for f in file_paths}
        for future in concurrent.futures.as_completed(future_to_file):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception as e:
                file_path = future_to_file[future]
                print(f"  Unexpected error processing {file_path}: {e}")
                results.append({
                    "file": os.path.basename(file_path),
                    "status": "error",
                    "message": str(e)
                })

    valid_count = sum(1 for r in results if r["status"] == "valid")
    invalid_count = sum(1 for r in results if r["status"] == "invalid")
    error_count = sum(1 for r in results if r["status"] == "error")

    valid_results = [r for r in results if r["status"] == "valid"]
    if valid_results:
        # Apply user's sorting preference
        user_id = update.effective_user.id
        sort_preference = USER_SORT_PREFERENCES.get(user_id, "credits_desc")  # Default to credits descending

        if sort_preference == "plan_asc":
            valid_results.sort(key=lambda x: x.get("plan", ""))
        elif sort_preference == "plan_desc":
            valid_results.sort(key=lambda x: x.get("plan", ""), reverse=True)
        elif sort_preference == "credits_asc":
            valid_results.sort(key=lambda x: x.get("total_with_refresh", 0))
        elif sort_preference == "credits_desc":
            valid_results.sort(key=lambda x: x.get("total_with_refresh", 0), reverse=True)
        elif sort_preference == "email_asc":
            valid_results.sort(key=lambda x: x.get("email", ""))
        elif sort_preference == "email_desc":
            valid_results.sort(key=lambda x: x.get("email", ""), reverse=True)
        elif sort_preference == "renewal_asc":
            valid_results.sort(key=lambda x: x.get("renewal_date", ""))
        elif sort_preference == "renewal_desc":
            valid_results.sort(key=lambda x: x.get("renewal_date", ""), reverse=True)

    # ── Build compact Telegram summary (counts by plan) ──
    plan_counts = Counter(r.get('plan', 'Unknown') for r in valid_results)
    total_credits_all = sum(r.get('total_with_refresh', 0) for r in valid_results)

    summary_message = (
        f"✨ Validation complete! ✨\n\n"
        f"📊 Results:\n"
        f"  ✅ Valid:   {valid_count}\n"
        f"  ❌ Invalid: {invalid_count}\n"
        f"  ⚠️ Errors:  {error_count}\n"
    )

    if valid_results:
        summary_message += f"\n📋 Breakdown by Plan:\n"
        # Sort plans in a logical order
        plan_order = ['Max', 'Pro', 'Plus', 'Team', 'Casual', 'Free']
        for plan_name in plan_order:
            if plan_name in plan_counts:
                summary_message += f"  🏆 {plan_name}: {plan_counts[plan_name]}\n"
        # Include any plans not in the predefined order
        for plan_name, count in sorted(plan_counts.items()):
            if plan_name not in plan_order:
                summary_message += f"  🏆 {plan_name}: {count}\n"

        summary_message += f"\n💳 Total Credits: {total_credits_all}\n"
        summary_message += f"\n📎 Full details are in the attached summary.txt"

    await update.message.reply_text(summary_message)

    # ── Build detailed summary.txt for the zip ──
    if valid_results:
        detailed_lines = []
        detailed_lines.append("=" * 60)
        detailed_lines.append("       COOKIE VALIDATION REPORT")
        detailed_lines.append("=" * 60)
        detailed_lines.append(f"")
        detailed_lines.append(f"Total Checked:  {len(results)}")
        detailed_lines.append(f"Valid:          {valid_count}")
        detailed_lines.append(f"Invalid:        {invalid_count}")
        detailed_lines.append(f"Errors:         {error_count}")
        detailed_lines.append(f"")
        detailed_lines.append("-" * 60)
        detailed_lines.append("BREAKDOWN BY PLAN")
        detailed_lines.append("-" * 60)
        for plan_name in plan_order:
            if plan_name in plan_counts:
                detailed_lines.append(f"  {plan_name}: {plan_counts[plan_name]}")
        for plan_name, count in sorted(plan_counts.items()):
            if plan_name not in plan_order:
                detailed_lines.append(f"  {plan_name}: {count}")
        detailed_lines.append(f"")
        detailed_lines.append(f"Total Credits: {total_credits_all}")
        detailed_lines.append(f"")
        detailed_lines.append("-" * 60)
        detailed_lines.append("VALID COOKIES DETAILS")
        detailed_lines.append("-" * 60)
        for i, r in enumerate(valid_results, 1):
            detailed_lines.append(f"")
            detailed_lines.append(f"  [{i}] {r.get('email', 'N/A')}")
            detailed_lines.append(f"      Plan:            {r.get('plan', 'N/A')}")
            detailed_lines.append(f"      Billing:         {r.get('billing', 'N/A')}")
            detailed_lines.append(f"      Credits:         {r.get('total_with_refresh', 0)}")
            detailed_lines.append(f"      Monthly Limit:   {r.get('monthly_credits_limit', 0)}")
            detailed_lines.append(f"      Daily Refresh:   {r.get('daily_refresh_credits', 0)}")
            detailed_lines.append(f"      Max Refresh:     {r.get('max_refresh_credits', 0)}")
            detailed_lines.append(f"      Free Credits:    {r.get('free_credits', 0)}")
            detailed_lines.append(f"      Periodic:        {r.get('periodic_credits', 0)}")
            detailed_lines.append(f"      Add-on:          {r.get('addon_credits', 0)}")
            detailed_lines.append(f"      Renewal:         {r.get('renewal_date', 'N/A')}")
            detailed_lines.append(f"      Name:            {r.get('name', 'N/A')}")
            detailed_lines.append(f"      Output File:     {r.get('output_file', 'N/A')}")
        detailed_lines.append(f"")
        detailed_lines.append("=" * 60)

        summary_file_path = os.path.join(OUTPUT_DIR, "summary.txt")
        with open(summary_file_path, 'w', encoding='utf-8') as sf:
            sf.write("\n".join(detailed_lines) + "\n")

    # Create a zip file of all validated cookies and the summary.txt
    if valid_count > 0:
        output_zip_path = os.path.join(OUTPUT_DIR, "validated_cookies.zip")
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(OUTPUT_DIR):
                for file in files:
                    # Only add .txt files (cookies and summary.txt)
                    if file.endswith('.txt'):
                        zf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), OUTPUT_DIR))

        await update.message.reply_document(document=open(output_zip_path, 'rb'))
        os.remove(output_zip_path)  # Clean up the output zip file
        summary_file_path = os.path.join(OUTPUT_DIR, "summary.txt")
        if os.path.exists(summary_file_path):
            os.remove(summary_file_path)  # Clean up the summary.txt file

    # Clean up input cookie files
    for f in file_paths:
        if os.path.exists(f):
            os.remove(f)


async def sort_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        [InlineKeyboardButton("Plan (A-Z)", callback_data="plan_asc"),
         InlineKeyboardButton("Plan (Z-A)", callback_data="plan_desc")],
        [InlineKeyboardButton("Credits (Low-High)", callback_data="credits_asc"),
         InlineKeyboardButton("Credits (High-Low)", callback_data="credits_desc")],
        [InlineKeyboardButton("Email (A-Z)", callback_data="email_asc"),
         InlineKeyboardButton("Email (Z-A)", callback_data="email_desc")],
        [InlineKeyboardButton("Renewal (Soonest-Latest)", callback_data="renewal_asc"),
         InlineKeyboardButton("Renewal (Latest-Soonest)", callback_data="renewal_desc")],
        [InlineKeyboardButton("Cancel", callback_data="cancel")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Select sorting preference:", reply_markup=reply_markup)
    return SELECTING_SORT_OPTION


async def select_sort_option(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    sort_preference = query.data

    if sort_preference == "cancel":
        await query.edit_message_text("Sorting preference selection cancelled.")
    else:
        user_id = update.effective_user.id
        USER_SORT_PREFERENCES[user_id] = sort_preference
        await query.edit_message_text(f"Sorting preference set to: {sort_preference.replace('_', ' ').title()}")
    return ConversationHandler.END


def main() -> None:
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("sort", sort_command)],
        states={
            SELECTING_SORT_OPTION: [CallbackQueryHandler(select_sort_option)],
        },
        fallbacks=[CommandHandler("cancel", select_sort_option)],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(conv_handler)
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
