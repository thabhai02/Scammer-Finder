import logging
import os
import re
import time
import json
import string
from collections import Counter
from threading import Thread
from datetime import datetime
from flask import Flask
from telegram import (
    InlineKeyboardButton, 
    InlineKeyboardMarkup, 
    Update,
    InputMediaPhoto
)
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Configuration ---
BOT_TOKEN = os.environ.get('BOT_TOKEN', '8201226423:AAEcdcAM3KOSfnoEwnwhr-5lqIkqbFuf1QU')
ADMIN_USER_IDS = [int(x) for x in os.environ.get('ADMIN_USER_IDS', '6103934030').split(',') if x]

# Protected identifiers that should never be stored
PROTECTED_IDENTIFIERS = {
    'upi': ['raj.n@fam', 'nitinraj3884@oksbi'],
    'phone': ['9204465448','7277839446'],
    'telegram': ['@trendhiveacademy'],
    'instagram': ['@trendhiveacademy']
}

# File paths for storing data
SCAM_FILES = {
    'upi': 'scam_upi.json',
    'phone': 'scam_phone.json',
    'telegram': 'scam_telegram.json',
    'instagram': 'scam_instagram.json',
}
SCAMMER_INFO_FILE = 'scammer_info.json'
ANALYTICS_FILE = 'analytics.json'
BLACKLIST_FILE = 'blacklist.json'

# Analytics counters
analytics_data = {
    "total_reports": 0,
    "total_checks": 0,
    "reports_today": 0,
    "checks_today": 0,
    "last_report_date": "",
    "last_check_date": "",
    "report_types": {"upi": 0, "phone": 0, "telegram": 0, "instagram": 0},
    "top_keywords": {},
    "user_activity": {}
}

# Stop words for keyword analysis
STOP_WORDS = {
    'a', 'an', 'the', 'and', 'or', 'but', 'if', 'then', 'else', 'when', 'at', 'from', 
    'by', 'on', 'off', 'for', 'in', 'out', 'over', 'to', 'into', 'with', 'about', 
    'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 
    'does', 'did', 'will', 'would', 'should', 'can', 'could', 'may', 'might', 'must', 
    'shall', 'should', 'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 
    'you', 'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his', 'himself', 
    'she', 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they', 'them', 'their', 
    'theirs', 'themselves', 'what', 'which', 'who', 'whom', 'this', 'that', 'these', 
    'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 
    'had', 'do', 'does', 'did', 'will', 'would', 'should', 'can', 'could', 'may', 
    'might', 'must', 'shall', 'should', 'here', 'there', 'when', 'where', 'why', 'how', 
    'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 
    'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 
    'will', 'just', 'don', 'should', 'now'
}

# --- User State Management ---
user_state = {}
user_reports = {}  # Stores user's reports for management

# --- Helper Functions ---

def load_data(filename: str) -> dict:
    """Load JSON data from file."""
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading {filename}: {e}")
    return {}

def save_data(filename: str, data: dict):
    """Save JSON data to file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved data to {filename}")
        return True
    except IOError as e:
        logger.error(f"Error saving to {filename}: {e}")
        return False

def is_protected_identifier(scam_type: str, identifier: str) -> bool:
    """Check if identifier is protected."""
    identifier = identifier.lower().strip()
    protected_list = PROTECTED_IDENTIFIERS.get(scam_type, [])
    return any(protected_id.lower() in identifier for protected_id in protected_list)

def update_analytics(event_type: str, user_id: int = None, story: str = None, scam_type: str = None):
    """Update analytics data."""
    global analytics_data

    # Load existing analytics
    analytics_data = load_data(ANALYTICS_FILE) or analytics_data

    # Update counts
    today = datetime.now().strftime('%Y-%m-%d')

    if event_type == 'report':
        analytics_data['total_reports'] += 1
        analytics_data['report_types'][scam_type] = analytics_data['report_types'].get(scam_type, 0) + 1

        # Reset daily counter if new day
        if analytics_data.get('last_report_date') != today:
            analytics_data['reports_today'] = 0
        analytics_data['reports_today'] += 1
        analytics_data['last_report_date'] = today

        # Update user activity
        user_activity = analytics_data['user_activity'].get(str(user_id), {})
        user_activity['reports'] = user_activity.get('reports', 0) + 1
        analytics_data['user_activity'][str(user_id)] = user_activity

        # Update keywords
        if story:
            # Clean and tokenize story
            translator = str.maketrans('', '', string.punctuation)
            clean_story = story.translate(translator).lower()
            words = clean_story.split()

            # Count relevant keywords
            for word in words:
                if word not in STOP_WORDS and len(word) > 3:
                    analytics_data['top_keywords'][word] = analytics_data['top_keywords'].get(word, 0) + 1

    elif event_type == 'check':
        analytics_data['total_checks'] += 1

        # Reset daily counter if new day
        if analytics_data.get('last_check_date') != today:
            analytics_data['checks_today'] = 0
        analytics_data['checks_today'] += 1
        analytics_data['last_check_date'] = today

        # Update user activity
        user_activity = analytics_data['user_activity'].get(str(user_id), {})
        user_activity['checks'] = user_activity.get('checks', 0) + 1
        analytics_data['user_activity'][str(user_id)] = user_activity

    # Save updated analytics
    save_data(ANALYTICS_FILE, analytics_data)

def get_reputation_score(reports: list) -> tuple:
    """Calculate reputation score based on reports."""
    if not reports:
        return 0, "✅ Safe"

    report_count = len(reports)

    if report_count == 1:
        return 1, "⚠️ Low Risk"
    elif 2 <= report_count <= 3:
        return 2, "⚠️⚠️ Medium Risk"
    elif 4 <= report_count <= 5:
        return 3, "⚠️⚠️⚠️ High Risk"
    else:
        return 4, "🚨🚨🚨🚨 Severe Risk"

def add_report(user_id: int, scam_type: str, identifier: str, story: str, proof: list = None) -> bool:
    """Add a new scam report."""
    timestamp = int(time.time())
    report = {
        'user_id': user_id,
        'scam_type': scam_type,
        'identifier': identifier,
        'story': story,
        'timestamp': timestamp,
        'proof': proof or []
    }

    # Save to specific scam type file
    specific_file = SCAM_FILES.get(scam_type)
    if specific_file:
        data = load_data(specific_file)
        if identifier not in data:
            data[identifier] = []
        data[identifier].append(report)
        if not save_data(specific_file, data):
            return False

    # Save to general scammer info file
    general_data = load_data(SCAMMER_INFO_FILE)
    key = f"{scam_type}_{identifier}_{timestamp}_{user_id}"
    general_data[key] = report

    # Update analytics
    update_analytics('report', user_id, story, scam_type)

    return save_data(SCAMMER_INFO_FILE, general_data)

def get_report(report_key: str) -> dict:
    """Get a specific report by its key."""
    general_data = load_data(SCAMMER_INFO_FILE)
    return general_data.get(report_key)

def update_report(report_key: str, new_data: dict) -> bool:
    """Update an existing report."""
    general_data = load_data(SCAMMER_INFO_FILE)

    if report_key not in general_data:
        return False

    # Update the report
    report = general_data[report_key]
    for field, value in new_data.items():
        if field in report:
            report[field] = value

    # Save updated data
    general_data[report_key] = report

    # Also update specific scam file
    scam_type = report['scam_type']
    identifier = report['identifier']
    specific_file = SCAM_FILES.get(scam_type)

    if specific_file:
        data = load_data(specific_file)
        if identifier in data:
            # Find and update the matching report
            for i, r in enumerate(data[identifier]):
                if (r['user_id'] == report['user_id'] and 
                    r['timestamp'] == report['timestamp']):
                    data[identifier][i] = report
                    save_data(specific_file, data)
                    break

    return save_data(SCAMMER_INFO_FILE, general_data)

def get_user_reports(user_id: int) -> dict:
    """Get all reports submitted by a user."""
    user_reports = {}
    general_data = load_data(SCAMMER_INFO_FILE)

    for key, report in general_data.items():
        if report.get('user_id') == user_id:
            user_reports[key] = report

    return user_reports

def get_all_reports() -> dict:
    """Get all reports in the system."""
    return load_data(SCAMMER_INFO_FILE) or {}

def delete_report(report_key: str) -> bool:
    """Delete a report from all files."""
    # Load the report to get details
    general_data = load_data(SCAMMER_INFO_FILE)
    report = general_data.get(report_key)
    if not report:
        return False

    # Delete from specific file
    scam_type = report['scam_type']
    identifier = report['identifier']
    specific_file = SCAM_FILES.get(scam_type)
    if specific_file:
        data = load_data(specific_file)
        if identifier in data:
            # Remove all reports for this identifier by this user
            data[identifier] = [r for r in data[identifier] if r['user_id'] != report['user_id']]
            if not data[identifier]:  # If no more reports, remove identifier
                del data[identifier]
            save_data(specific_file, data)

    # Delete from general file
    if report_key in general_data:
        del general_data[report_key]
        return save_data(SCAMMER_INFO_FILE, general_data)

    return False

def clear_all_data():
    """Clear all scam data files."""
    for file in list(SCAM_FILES.values()) + [SCAMMER_INFO_FILE]:
        try:
            if os.path.exists(file):
                os.remove(file)
                logger.info(f"Deleted {file}")
        except OSError as e:
            logger.error(f"Error deleting {file}: {e}")
    return True

def search_reports(scam_type: str, search_id: str) -> list:
    """Search for reports matching an identifier."""
    specific_file = SCAM_FILES.get(scam_type)
    if not specific_file:
        return []

    data = load_data(specific_file)
    search_id = search_id.lower().strip()

    # Find all matching identifiers (case-insensitive)
    results = []
    for identifier, reports in data.items():
        if search_id in identifier.lower():
            results.extend(reports)

    return results

def is_blacklisted(user_id: int) -> bool:
    """Check if user is blacklisted."""
    blacklist = load_data(BLACKLIST_FILE) or {}
    return str(user_id) in blacklist

def blacklist_user(user_id: int, reason: str = "Violation of terms"):
    """Add user to blacklist."""
    blacklist = load_data(BLACKLIST_FILE) or {}
    blacklist[str(user_id)] = {
        'timestamp': int(time.time()),
        'reason': reason
    }
    return save_data(BLACKLIST_FILE, blacklist)

def unblacklist_user(user_id: int) -> bool:
    """Remove user from blacklist."""
    blacklist = load_data(BLACKLIST_FILE) or {}
    if str(user_id) in blacklist:
        del blacklist[str(user_id)]
        return save_data(BLACKLIST_FILE, blacklist)
    return False

def get_top_keywords(n=10) -> list:
    """Get top keywords from analytics."""
    analytics = load_data(ANALYTICS_FILE) or {}
    keywords = analytics.get('top_keywords', {})
    return Counter(keywords).most_common(n)

def get_active_users() -> list:
    """Get most active users."""
    analytics = load_data(ANALYTICS_FILE) or {}
    user_activity = analytics.get('user_activity', {})

    # Create list of (user_id, total_actions)
    active_users = []
    for user_id, data in user_activity.items():
        total_actions = data.get('reports', 0) + data.get('checks', 0)
        active_users.append((user_id, total_actions))

    # Sort by total actions descending
    return sorted(active_users, key=lambda x: x[1], reverse=True)[:10]

# --- Command Handlers ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Sends welcome message with main menu."""
    user = update.effective_user

    # Check if user is blacklisted
    if is_blacklisted(user.id):
        await update.message.reply_text(
            "⛔ Your account has been blacklisted from using this service. "
            "Contact support if you believe this is an error."
        )
        return

    return await show_main_menu(update, context)

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, message=None):
    """Shows the main menu with options."""
    user = update.effective_user

    keyboard = [
        [InlineKeyboardButton("🚨 Report Scammer", callback_data='report_scammer')],
        [InlineKeyboardButton("🔍 Check Scammer", callback_data='check_scammer')],
        [InlineKeyboardButton("📝 My Reports", callback_data='my_reports')],
    ]

    # Add admin panel for admins
    if user.id in ADMIN_USER_IDS:
        keyboard.append([InlineKeyboardButton("🛠 Admin Panel", callback_data='admin_panel')])

    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "👋 Welcome! I'm your Scammer Reporting Bot. How can I help you today?"

    if message:
        await message.reply_text(text, reply_markup=reply_markup)
    elif update.callback_query:
        query = update.callback_query
        await query.edit_message_text(text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(text, reply_markup=reply_markup)

# --- Callback Query Handler ---

async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles inline button presses."""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data

    # Check if user is blacklisted
    if is_blacklisted(user_id):
        await query.edit_message_text(
            "⛔ Your account has been blacklisted from using this service. "
            "Contact support if you believe this is an error."
        )
        return

    if data == 'report_scammer':
        keyboard = [
            [InlineKeyboardButton("💳 UPI ID", callback_data='report_type_upi')],
            [InlineKeyboardButton("📞 Phone Number", callback_data='report_type_phone')],
            [InlineKeyboardButton("✈️ Telegram", callback_data='report_type_telegram')],
            [InlineKeyboardButton("📸 Instagram", callback_data='report_type_instagram')],
            [InlineKeyboardButton("⬅️ Back", callback_data='back_to_main')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "Which type of identifier do you want to report? 👇",
            reply_markup=reply_markup
        )
    elif data.startswith('report_type_'):
        scam_type = data.split('_')[2]
        user_state[user_id] = {'action': 'awaiting_id', 'type': scam_type}
        await query.edit_message_text(
            f"Okay, please send me the {scam_type.upper()} of the scammer. 📝\n\n"
            "⚠️ Note: Some protected identifiers cannot be reported."
        )
    elif data == 'check_scammer':
        keyboard = [
            [InlineKeyboardButton("💳 UPI ID", callback_data='check_type_upi')],
            [InlineKeyboardButton("📞 Phone Number", callback_data='check_type_phone')],
            [InlineKeyboardButton("✈️ Telegram", callback_data='check_type_telegram')],
            [InlineKeyboardButton("📸 Instagram", callback_data='check_type_instagram')],
            [InlineKeyboardButton("⬅️ Back", callback_data='back_to_main')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "Which type of identifier do you want to check? 👇",
            reply_markup=reply_markup
        )
    elif data.startswith('check_type_'):
        scam_type = data.split('_')[2]
        user_state[user_id] = {'action': 'awaiting_check_id', 'type': scam_type}
        await query.edit_message_text(
            f"Please send me the {scam_type.upper()} you want to check. 🔎"
        )
    elif data == 'my_reports':
        await handle_my_reports(update, context)
    elif data == 'admin_panel' and user_id in ADMIN_USER_IDS:
        await handle_admin_panel(update, context)
    elif data == 'clear_all_data' and user_id in ADMIN_USER_IDS:
        if clear_all_data():
            await query.edit_message_text("✅ All scam data has been cleared!")
        else:
            await query.edit_message_text("❌ Failed to clear data.")
        # Show main menu after action
        await show_main_menu(update, context)
    elif data.startswith('delete_report_'):
        report_key = data[len('delete_report_'):]
        if delete_report(report_key):
            await query.edit_message_text("✅ Report deleted successfully!")
        else:
            await query.edit_message_text("❌ Failed to delete report.")
        await handle_my_reports(update, context)
    elif data == 'back_to_main':
        await show_main_menu(update, context)
    elif data == 'admin_view_reports':
        user_state[user_id] = {'action': 'admin_search_reports'}
        await query.edit_message_text(
            "🔍 Enter the identifier to search for (partial matches accepted):"
        )
    elif data == 'admin_blacklist':
        keyboard = [
            [InlineKeyboardButton("➕ Blacklist User", callback_data='admin_blacklist_add')],
            [InlineKeyboardButton("➖ Unblacklist User", callback_data='admin_blacklist_remove')],
            [InlineKeyboardButton("⬅️ Back", callback_data='admin_panel')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "🛑 Blacklist Management:",
            reply_markup=reply_markup
        )
    elif data == 'admin_blacklist_add':
        user_state[user_id] = {'action': 'admin_blacklist_add'}
        await query.edit_message_text(
            "Enter the user ID to blacklist:"
        )
    elif data == 'admin_blacklist_remove':
        user_state[user_id] = {'action': 'admin_blacklist_remove'}
        await query.edit_message_text(
            "Enter the user ID to unblacklist:"
        )
    elif data == 'admin_analytics':
        await show_analytics(update, context)
    elif data == 'admin_panel_back':
        await handle_admin_panel(update, context)
    elif data == 'admin_view_all_reports':
        await show_all_reports(update, context, page=0)
    elif data.startswith('admin_report_page_'):
        page = int(data.split('_')[-1])
        await show_all_reports(update, context, page)
    elif data.startswith('admin_view_report_'):
        report_key = data[len('admin_view_report_'):]
        await view_report_details(update, context, report_key)
    elif data.startswith('admin_edit_report_'):
        report_key = data[len('admin_edit_report_'):]
        user_state[user_id] = {
            'action': 'admin_editing_report',
            'report_key': report_key,
            'field': None
        }
        await show_edit_options(update, context, report_key)
    elif data.startswith('admin_edit_field_'):
        parts = data.split('_')
        report_key = parts[3]
        field = parts[4]
        user_state[user_id] = {
            'action': 'admin_editing_field',
            'report_key': report_key,
            'field': field
        }
        report = get_report(report_key)
        current_value = report.get(field, '')
        await query.edit_message_text(
            f"✏️ Editing {field.upper()} for report:\n"
            f"Current value: {current_value}\n\n"
            "Please send the new value:"
        )
    elif data.startswith('admin_delete_report_'):
        report_key = data[len('admin_delete_report_'):]
        if delete_report(report_key):
            await query.answer("✅ Report deleted!")
            # Return to report list
            if user_id in user_state and user_state[user_id].get('action') == 'admin_view_all_reports':
                page = user_state[user_id].get('page', 0)
                await show_all_reports(update, context, page)
            else:
                await handle_admin_panel(update, context)
        else:
            await query.answer("❌ Failed to delete report.")
    else:
        await query.edit_message_text("Invalid option. Please try again.")

async def show_all_reports(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 0):
    """Show all reports to admin with pagination."""
    query = update.callback_query
    user_id = query.from_user.id

    # Save current page in state
    user_state[user_id] = {'action': 'admin_view_all_reports', 'page': page}

    reports = get_all_reports()
    if not reports:
        keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data='admin_panel_back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "No reports found in the database.",
            reply_markup=reply_markup
        )
        return

    # Sort reports by timestamp (newest first)
    sorted_reports = sorted(reports.items(), key=lambda x: x[1].get('timestamp', 0), reverse=True)

    # Pagination
    items_per_page = 5
    total_pages = (len(sorted_reports) + items_per_page - 1) // items_per_page

    if page >= total_pages:
        page = total_pages - 1

    start_idx = page * items_per_page
    end_idx = min(start_idx + items_per_page, len(sorted_reports))
    page_reports = sorted_reports[start_idx:end_idx]

    # Format message
    message = f"📋 All Reports (Page {page+1}/{total_pages}):\n\n"

    for i, (report_key, report) in enumerate(page_reports, start=1):
        timestamp = time.strftime('%Y-%m-%d %H:%M', time.localtime(report['timestamp']))
        message += (
            f"🔹 Report #{start_idx + i}\n"
            f"Type: {report['scam_type'].upper()}\n"
            f"Identifier: {report['identifier']}\n"
            f"Date: {timestamp}\n"
            f"User: {report['user_id']}\n"
            f"Key: `{report_key[:15]}...`\n\n"
        )

    # Create keyboard
    keyboard = []

    # Add view buttons for each report
    for i, (report_key, _) in enumerate(page_reports, start=1):
        keyboard.append([
            InlineKeyboardButton(
                f"View Report #{start_idx + i}", 
                callback_data=f'admin_view_report_{report_key}'
            )
        ])

    # Pagination buttons
    nav_buttons = []
    if page > 0:
        nav_buttons.append(InlineKeyboardButton("⬅️ Previous", callback_data=f'admin_report_page_{page-1}'))
    if page < total_pages - 1:
        nav_buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f'admin_report_page_{page+1}'))

    if nav_buttons:
        keyboard.append(nav_buttons)

    # Add back button
    keyboard.append([InlineKeyboardButton("🔙 Back to Admin", callback_data='admin_panel_back')])

    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(message, reply_markup=reply_markup, parse_mode='Markdown')

async def view_report_details(update: Update, context: ContextTypes.DEFAULT_TYPE, report_key: str):
    """Show detailed view of a specific report."""
    query = update.callback_query
    report = get_report(report_key)

    if not report:
        await query.answer("Report not found!")
        return

    timestamp = time.strftime('%Y-%m-%d %H:%M', time.localtime(report['timestamp']))

    message = (
        f"🔍 Report Details:\n\n"
        f"🔑 Key: `{report_key}`\n"
        f"👤 User ID: {report['user_id']}\n"
        f"📝 Type: {report['scam_type'].upper()}\n"
        f"🔢 Identifier: {report['identifier']}\n"
        f"📅 Date: {timestamp}\n\n"
        f"📖 Story:\n{report['story']}\n\n"
        f"📸 Proof: {len(report.get('proof', []))} items"
    )

    keyboard = [
        [
            InlineKeyboardButton("✏️ Edit Report", callback_data=f'admin_edit_report_{report_key}'),
            InlineKeyboardButton("🗑 Delete Report", callback_data=f'admin_delete_report_{report_key}')
        ],
        [InlineKeyboardButton("⬅️ Back to Reports", callback_data='admin_view_all_reports')]
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(message, reply_markup=reply_markup, parse_mode='Markdown')

async def show_edit_options(update: Update, context: ContextTypes.DEFAULT_TYPE, report_key: str):
    """Show options for editing a report."""
    query = update.callback_query
    report = get_report(report_key)

    if not report:
        await query.answer("Report not found!")
        return

    message = "✏️ Select which field to edit:"

    keyboard = [
        [InlineKeyboardButton("Edit Scam Type", callback_data=f'admin_edit_field_{report_key}_scam_type')],
        [InlineKeyboardButton("Edit Identifier", callback_data=f'admin_edit_field_{report_key}_identifier')],
        [InlineKeyboardButton("Edit Story", callback_data=f'admin_edit_field_{report_key}_story')],
        [InlineKeyboardButton("⬅️ Back to Report", callback_data=f'admin_view_report_{report_key}')]
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(message, reply_markup=reply_markup)

async def handle_my_reports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show user's submitted reports."""
    query = update.callback_query
    user_id = query.from_user.id

    reports = get_user_reports(user_id)
    if not reports:
        keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data='back_to_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "You haven't submitted any reports yet.",
            reply_markup=reply_markup
        )
        return

    # Format reports for display
    message = "📋 Your Submitted Reports:\n\n"
    keyboard = []

    for i, (report_key, report) in enumerate(reports.items(), 1):
        timestamp = time.strftime('%Y-%m-%d %H:%M', time.localtime(report['timestamp']))
        message += (
            f"🔹 Report #{i}\n"
            f"Type: {report['scam_type'].upper()}\n"
            f"Identifier: {report['identifier']}\n"
            f"Date: {timestamp}\n"
            f"Story: {report['story'][:50]}...\n\n"
        )
        keyboard.append([InlineKeyboardButton(
            f"Delete Report #{i}", 
            callback_data=f'delete_report_{report_key}'
        )])

    keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data='back_to_main')])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(message, reply_markup=reply_markup)

async def handle_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show admin controls."""
    query = update.callback_query
    keyboard = [
        [InlineKeyboardButton("🔍 View Reports", callback_data='admin_view_reports')],
        [InlineKeyboardButton("📋 View All Reports", callback_data='admin_view_all_reports')],
        [InlineKeyboardButton("🧹 Clear All Data", callback_data='clear_all_data')],
        [InlineKeyboardButton("🛑 Manage Blacklist", callback_data='admin_blacklist')],
        [InlineKeyboardButton("📊 View Analytics", callback_data='admin_analytics')],
        [InlineKeyboardButton("⬅️ Back", callback_data='back_to_main')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        "🛠 Admin Panel - Use with caution!",
        reply_markup=reply_markup
    )

async def show_analytics(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot analytics."""
    query = update.callback_query
    analytics = load_data(ANALYTICS_FILE) or {}

    # Format analytics data
    message = "📊 Bot Analytics:\n\n"
    message += f"📈 Total Reports: {analytics.get('total_reports', 0)}\n"
    message += f"🔎 Total Checks: {analytics.get('total_checks', 0)}\n"
    message += f"📅 Reports Today: {analytics.get('reports_today', 0)}\n"
    message += f"🔍 Checks Today: {analytics.get('checks_today', 0)}\n\n"

    # Report types breakdown
    message += "📝 Report Types:\n"
    for rtype, count in analytics.get('report_types', {}).items():
        message += f"- {rtype.upper()}: {count}\n"

    # Top keywords
    message += "\n🔑 Top Keywords in Reports:\n"
    keywords = get_top_keywords(5)
    for i, (word, count) in enumerate(keywords, 1):
        message += f"{i}. {word} ({count})\n"

    # Active users
    message += "\n👥 Most Active Users:\n"
    active_users = get_active_users()
    for i, (user_id, actions) in enumerate(active_users, 1):
        message += f"{i}. User {user_id}: {actions} actions\n"

    keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data='admin_panel_back')]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(message, reply_markup=reply_markup)

# --- Message Handler ---

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Processes text messages based on user state."""
    user = update.effective_user
    user_id = user.id
    text = update.message.text if update.message else ""

    # Check if user is blacklisted
    if is_blacklisted(user_id):
        if update.message:
            await update.message.reply_text(
                "⛔ Your account has been blacklisted from using this service. "
                "Contact support if you believe this is an error."
            )
        return

    if user_id not in user_state:
        # Show main menu if user isn't in a specific state
        if update.message:
            await show_main_menu(update, context, message=update.message)
        return

    state = user_state[user_id]
    action = state.get('action')
    scam_type = state.get('type')

    if action == 'awaiting_id':
        identifier = text.strip()

        # Check for protected identifiers
        if is_protected_identifier(scam_type, identifier):
            await update.message.reply_text(
                "🚫 This identifier is protected and cannot be reported.\n"
                "Please report a different identifier or contact support."
            )
            del user_state[user_id]
            # Show main menu after rejection
            await show_main_menu(update, context, message=update.message)
            return

        user_state[user_id] = {
            'action': 'awaiting_story',
            'type': scam_type,
            'identifier': identifier
        }
        await update.message.reply_text(
            f"Got it! Now, please tell me the story of the scam. 📝\n\n"
            "Include details like:\n"
            "- How they contacted you\n"
            "- What they promised\n"
            "- How they scammed you\n"
            "- Amount lost (if any)"
        )
    elif action == 'awaiting_story':
        scam_story = text.strip()
        identifier = state.get('identifier')

        # Store story and request proof
        user_state[user_id] = {
            'action': 'awaiting_proof',
            'type': scam_type,
            'identifier': identifier,
            'story': scam_story
        }

        keyboard = [[InlineKeyboardButton("Skip Proof", callback_data='skip_proof')]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "📸 Please send screenshot(s), document(s), or link(s) as proof.\n"
            "You can send multiple files in one message.\n\n"
            "If you don't have proof, click Skip below.",
            reply_markup=reply_markup
        )
    elif action == 'admin_search_reports':
        search_term = text.strip().lower()
        general_data = load_data(SCAMMER_INFO_FILE)

        # Find matching reports
        matches = []
        for key, report in general_data.items():
            if search_term in report['identifier'].lower():
                matches.append((key, report))

        if not matches:
            await update.message.reply_text("❌ No matching reports found.")
            await handle_admin_panel(update, context)
            return

        # Format results
        message = f"🔍 Found {len(matches)} matching reports:\n\n"
        for i, (key, report) in enumerate(matches[:5], 1):
            timestamp = time.strftime('%Y-%m-%d', time.localtime(report['timestamp']))
            message += (
                f"🔹 Report #{i}\n"
                f"Key: {key}\n"
                f"Type: {report['scam_type'].upper()}\n"
                f"Identifier: {report['identifier']}\n"
                f"Date: {timestamp}\n"
                f"Story: {report['story'][:50]}...\n\n"
            )

        message += "Showing first 5 results. Use the report key to delete if needed."
        await update.message.reply_text(message)
        await handle_admin_panel(update, context)
    elif action == 'admin_blacklist_add':
        try:
            target_user_id = int(text.strip())
            if blacklist_user(target_user_id):
                await update.message.reply_text(f"✅ User {target_user_id} has been blacklisted.")
            else:
                await update.message.reply_text("❌ Failed to blacklist user.")
        except ValueError:
            await update.message.reply_text("❌ Invalid user ID. Please enter a numeric ID.")
        await handle_admin_panel(update, context)
    elif action == 'admin_blacklist_remove':
        try:
            target_user_id = int(text.strip())
            if unblacklist_user(target_user_id):
                await update.message.reply_text(f"✅ User {target_user_id} has been unblacklisted.")
            else:
                await update.message.reply_text("❌ User not found in blacklist or failed to unblacklist.")
        except ValueError:
            await update.message.reply_text("❌ Invalid user ID. Please enter a numeric ID.")
        await handle_admin_panel(update, context)
    elif action == 'admin_editing_field':
        report_key = state.get('report_key')
        field = state.get('field')
        new_value = text.strip()

        if update_report(report_key, {field: new_value}):
            await update.message.reply_text(f"✅ {field.upper()} updated successfully!")
            # Show report details again
            await context.bot.send_message(
                chat_id=user_id,
                text="Returning to report details...",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton(
                        "🔙 Back to Report", 
                        callback_data=f'admin_view_report_{report_key}'
                    )]
                ])
            )
        else:
            await update.message.reply_text("❌ Failed to update report.")

        # Clear editing state
        if user_id in user_state:
            del user_state[user_id]
    else:
        await update.message.reply_text(
            "Please select an option from the menu or use /start."
        )
        # Show main menu for unrecognized state
        await show_main_menu(update, context, message=update.message)

async def handle_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle photo/document uploads for proof."""
    user = update.effective_user
    user_id = user.id

    if user_id not in user_state or user_state[user_id].get('action') != 'awaiting_proof':
        return

    state = user_state[user_id]
    proof = state.get('proof', [])

    # Handle photos
    if update.message.photo:
        photo = update.message.photo[-1]  # Get highest resolution
        proof.append({
            'type': 'photo',
            'file_id': photo.file_id,
            'caption': update.message.caption or ""
        })

    # Handle documents
    elif update.message.document:
        document = update.message.document
        proof.append({
            'type': 'document',
            'file_id': document.file_id,
            'file_name': document.file_name,
            'caption': update.message.caption or ""
        })

    # Update state with new proof
    user_state[user_id]['proof'] = proof

    # Confirm receipt
    await update.message.reply_text(
        f"✅ Proof received! You've added {len(proof)} proof item(s).\n"
        "Send more proof or click 'Done' when finished.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Done", callback_data='proof_done')],
            [InlineKeyboardButton("📸 Add More", callback_data='add_more_proof')]
        ])
    )

async def handle_media_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle proof-related callback queries."""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id

    if user_id not in user_state or user_state[user_id].get('action') != 'awaiting_proof':
        return

    data = query.data

    if data == 'proof_done':
        # Finalize report
        state = user_state[user_id]
        if add_report(user_id, state['type'], state['identifier'], state['story'], state.get('proof')):
            await query.edit_message_text(
                f"✅ Report for {state['identifier']} saved with {len(state.get('proof', []))} proof item(s)!\n"
                "Thank you for helping fight scams! 💪"
            )
        else:
            await query.edit_message_text(
                "❌ Failed to save report. Please try again later."
            )
        del user_state[user_id]
        # Show main menu after submission
        await show_main_menu(update, context)
    elif data == 'add_more_proof':
        await query.edit_message_text(
            "📸 Please send another screenshot, document, or link as proof."
        )
    elif data == 'skip_proof':
        # Finalize report without proof
        state = user_state[user_id]
        if add_report(user_id, state['type'], state['identifier'], state['story']):
            await query.edit_message_text(
                f"✅ Report for {state['identifier']} saved!\n"
                "Thank you for helping fight scams! 💪"
            )
        else:
            await query.edit_message_text(
                "❌ Failed to save report. Please try again later."
            )
        del user_state[user_id]
        # Show main menu after submission
        await show_main_menu(update, context)

async def handle_check_result(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process scammer check results."""
    user_id = update.message.from_user.id
    text = update.message.text

    if user_id not in user_state or user_state[user_id].get('action') != 'awaiting_check_id':
        return

    state = user_state[user_id]
    check_id = text.strip()
    reports = search_reports(state['type'], check_id)

    # Update analytics
    update_analytics('check', user_id)

    if reports:
        score, risk_level = get_reputation_score(reports)
        risk_stars = "⚠️" * score

        response = (
            f"{risk_stars}\n"
            f"🚨 WARNING! The {state['type'].upper()} `{check_id}` "
            f"has {len(reports)} scam reports! 🚨\n\n"
            f"Risk Level: {risk_level}\n\n"
            "Recent Reports:\n"
        )

        # Show most recent 3 reports
        reports.sort(key=lambda r: r['timestamp'], reverse=True)
        for i, report in enumerate(reports[:3], 1):
            timestamp = time.strftime('%Y-%m-%d', time.localtime(report['timestamp']))
            response += (
                f"{i}. 📅 {timestamp}: "
                f"{report['story'][:70]}...\n"
            )

        response += (
            f"\n⚠️ Be extremely cautious when interacting with this {state['type'].upper()}!"
        )
    else:
        response = (
            f"✅ The {state['type'].upper()} `{check_id}` has not been reported.\n"
            "However, always stay vigilant for new scams!"
        )

    await update.message.reply_text(response, parse_mode='Markdown')
    del user_state[user_id]
    # Show main menu after check
    await show_main_menu(update, context, message=update.message)

# --- Replit Keep-Alive Web Server ---
app = Flask(__name__)

@app.route('/')
def home():
    return "Scam Alert Bot is running!"

def run_flask_app():
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

# --- Main Function ---

def main():
    """Starts the bot and web server."""
    # Initialize data files
    for file in list(SCAM_FILES.values()) + [SCAMMER_INFO_FILE, ANALYTICS_FILE, BLACKLIST_FILE]:
        if not os.path.exists(file):
            save_data(file, {})

    # Start Flask in separate thread
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()
    logger.info("Flask web server started")

    # Create bot application
    application = Application.builder().token(BOT_TOKEN).build()

    # Register handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_callback_handler))
    application.add_handler(CallbackQueryHandler(handle_media_callback, pattern='^(proof_done|add_more_proof|skip_proof)$'))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_check_result))
    application.add_handler(MessageHandler(filters.PHOTO | filters.Document.ALL, handle_media))

    # Start polling
    logger.info("Bot started")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
