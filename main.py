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
import firebase_admin
from firebase_admin import credentials, db
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

# --- Firebase Initialization ---
def initialize_firebase():
    # Create a temporary file for Firebase credentials
    with open("temp_firebase_creds.json", "w") as f:
        json.dump({
            "type": "service_account",
            "project_id": "scam-safety-bot",
            "private_key_id": "552b226867dcada2694a1fe9ee90e21352d1e20e",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCKLh6Q68D3T/XI\nmrlQb/gu6zHicenr76/5LtqS8ej5hFdMWgluV9eL5uI1H4C4QKNiNHCefl55PCFj\nGmpe8ShU6Up50TaMozD0YrbD/X5KaPardU//PYjjtHB1GcyhIoJUmh2OFVJxVod/\noiE31MPGITGYtx9KlqtQVTzqlwm3z1T1x/YJ8oJCahsWfjgZcJNPr/EhEIJp56Gd\nMVbT2Nw01YI3eAHqzaKRgiZB+LirE/dgVWb3e1GAhbctP9UVRD5W3kqXLAjYRgAZ\nTH2lLkfV9CMJTk+W2OLEt+p/2pcJaefGwK5v88Vey1fTR09XR52S2lBLZJOcGoQ2\nnkiUoGT9AgMBAAECggEAGHdaCib0H9YUmtRqg4eP1h7m0kWBOblS2zgkk2gp7CQ2\noNpAWT1MeQUEgIt3ayhmxXiriCSv7Z9r+fQvaWgh0AcOnMsicXxjqqHf4ov71IkJ\nRAqdg4ANwOOuFc3foZhOo1Q2b3XvBwpfK4Y1g4E0uNwfv/6Ml9RduPeetZrQqa7V\nomn/byo7iugRdK5Wk/ry8oeSY5wIVPjL4mMvZeTmOwesbxGQQ6uKGFVpPXhXDueo\nzWjVL43zqiBNQiJxNin15zYKEyRseIF6cMGoIbSelojUVE9TjJFpAbvuM2dSVhgZ\npuUYR909KpcxtkZqDheMYv0CzKVtJNj+q55tUpN5MQKBgQDDBVtMmB7zl6e7b5Rs\nsswFlekMx0RT4di42XMkFK5gb1R59BJjZt4PTYeK2ExHpUEiFzBwMMNnorNt5v/0\n9l9Lr3En+RxEu6GCUNJkk2gcttqGIRf4hffWcJrTkE0KUwb5Iy6I2wHMi4dvQaoq\nFU/vvBQlPwrMe2/zO3HAdOf9hwKBgQC1YuML5qBnSNC/6UdDRnzd6H3N9Fmj9sgH\nffYbP+jTfTBjRaWzOdBiu70nTnWKitZ1KbFkuLTXmRQ4Gd5g8hV7O2pIctq9NU7q\noPDbT8tHu06sacOfyFH3srEqt6j0omOkzLiNP8E83cIuVqnB4dU1ao3ql69sttAU\nzmjIWC4KWwKBgHrPBr1nFiajm9am3zrMJTpnOsj3OwnvsQBGvwE7nMvRj8r0bhf2\nkWPlmLNQnkiHwkpre+9KZeL/TCqrSwfBliUdKA7aCnkmBwD/UF5RjUB3zYilkmjI\nRFfftUABIOKdgkilZQp9j9Z1DyZ6nWO+5AW91JnX5z75hHgROQLPG8BFAoGBAIvy\nySVUguxNxSpdDau9hfgdOnuejU8xx/Hn4OvzamtKyvu9L/TRpZOYMIBUS+Jh7sel\nLIZ+8KDsLip+4xI/lg1nsUBGxbh4mfPzywIbVcd5oGDslZABmiSYDZPc8pIVfPYZ\nMkdhKnIQ05K3MPEzkjJNjUO0Vxh1EKUNANGbH6LDAoGADGZoNg721ei4FZ+9fmOD\n9QXEQxmyh/4txjcInYknxIMOAuo1BMGKXze/V70k6cAyHKmHU7SLdHT0YcjQ7pzh\n6Su0P+9+2BD4OebH7my3exs3nwlwxpdbeVHE7jwQRVEFBJT4YsdbgJLOFDUzNZV+\nEs9SA2vbTBbofcrk8QEOAX0=\n-----END PRIVATE KEY-----\n",
            "client_email": "firebase-adminsdk-fbsvc@scam-safety-bot.iam.gserviceaccount.com",
            "client_id": "100808383445508811606",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40scam-safety-bot.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com"
        }, f)
    
    # Initialize Firebase
    cred = credentials.Certificate("temp_firebase_creds.json")
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://scam-safety-bot-default-rtdb.firebaseio.com/'
    })
    logger.info("Firebase initialized successfully")

# Initialize Firebase
initialize_firebase()

# --- Firebase Database References ---
SCAM_REPORTS_REF = db.reference('scamReports')
SCAMMER_INFO_REF = db.reference('scammerInfo')
ANALYTICS_REF = db.reference('analytics')
BLACKLIST_REF = db.reference('blacklist')

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

# --- Firebase Helper Functions ---
def firebase_get(path_ref):
    """Get data from Firebase reference."""
    try:
        data = path_ref.get()
        return data if data is not None else {}
    except Exception as e:
        logger.error(f"Firebase read error: {e}")
        return {}

def firebase_set(path_ref, data):
    """Save data to Firebase reference."""
    try:
        path_ref.set(data)
        logger.info(f"Firebase data saved to {path_ref.path}")
        return True
    except Exception as e:
        logger.error(f"Firebase write error: {e}")
        return False

def firebase_update(path_ref, updates):
    """Update specific fields in Firebase."""
    try:
        path_ref.update(updates)
        logger.info(f"Firebase data updated at {path_ref.path}")
        return True
    except Exception as e:
        logger.error(f"Firebase update error: {e}")
        return False

def firebase_delete(path_ref):
    """Delete data from Firebase."""
    try:
        path_ref.delete()
        logger.info(f"Firebase data deleted at {path_ref.path}")
        return True
    except Exception as e:
        logger.error(f"Firebase delete error: {e}")
        return False

def is_protected_identifier(scam_type: str, identifier: str) -> bool:
    """Check if identifier is protected."""
    identifier = identifier.lower().strip()
    protected_list = PROTECTED_IDENTIFIERS.get(scam_type, [])
    return any(protected_id.lower() in identifier for protected_id in protected_list)

def update_analytics(event_type: str, user_id: int = None, story: str = None, scam_type: str = None):
    """Update analytics data in Firebase."""
    global analytics_data
    
    # Load existing analytics
    analytics_data = firebase_get(ANALYTICS_REF) or analytics_data
    today = datetime.now().strftime('%Y-%m-%d')

    if event_type == 'report':
        # Update analytics data
        updates = {
            'total_reports': analytics_data.get('total_reports', 0) + 1,
            f'report_types/{scam_type}': analytics_data.get('report_types', {}).get(scam_type, 0) + 1
        }
        
        # Reset daily counter if new day
        if analytics_data.get('last_report_date') != today:
            updates['reports_today'] = 1
        else:
            updates['reports_today'] = analytics_data.get('reports_today', 0) + 1
            
        updates['last_report_date'] = today
        
        # Update user activity
        user_activity = analytics_data.get('user_activity', {}).get(str(user_id), {})
        user_activity['reports'] = user_activity.get('reports', 0) + 1
        updates[f'user_activity/{user_id}'] = user_activity

        # Update keywords
        if story:
            # Clean and tokenize story
            translator = str.maketrans('', '', string.punctuation)
            clean_story = story.translate(translator).lower()
            words = clean_story.split()

            # Count relevant keywords
            top_keywords = analytics_data.get('top_keywords', {})
            for word in words:
                if word not in STOP_WORDS and len(word) > 3:
                    top_keywords[word] = top_keywords.get(word, 0) + 1
            updates['top_keywords'] = top_keywords

        # Save to Firebase
        firebase_update(ANALYTICS_REF, updates)
        
        # Update local copy
        analytics_data.update(updates)

    elif event_type == 'check':
        # Update analytics data
        updates = {
            'total_checks': analytics_data.get('total_checks', 0) + 1
        }
        
        # Reset daily counter if new day
        if analytics_data.get('last_check_date') != today:
            updates['checks_today'] = 1
        else:
            updates['checks_today'] = analytics_data.get('checks_today', 0) + 1
            
        updates['last_check_date'] = today
        
        # Update user activity
        user_activity = analytics_data.get('user_activity', {}).get(str(user_id), {})
        user_activity['checks'] = user_activity.get('checks', 0) + 1
        updates[f'user_activity/{user_id}'] = user_activity

        # Save to Firebase
        firebase_update(ANALYTICS_REF, updates)
        
        # Update local copy
        analytics_data.update(updates)

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
    """Add a new scam report to Firebase."""
    timestamp = int(time.time())
    report_key = f"{scam_type}_{identifier}_{timestamp}_{user_id}"
    report = {
        'user_id': user_id,
        'scam_type': scam_type,
        'identifier': identifier,
        'story': story,
        'timestamp': timestamp,
        'proof': proof or []
    }

    # Save to scamReports
    scam_type_ref = SCAM_REPORTS_REF.child(scam_type)
    scam_type_data = firebase_get(scam_type_ref) or {}
    
    if identifier not in scam_type_data:
        scam_type_data[identifier] = []
    
    scam_type_data[identifier].append(report)
    firebase_set(scam_type_ref, scam_type_data)

    # Save to scammerInfo
    scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}
    scammer_info_data[report_key] = report
    firebase_set(SCAMMER_INFO_REF, scammer_info_data)

    # Update analytics
    update_analytics('report', user_id, story, scam_type)

    return True

def get_report(report_key: str) -> dict:
    """Get a specific report by its key."""
    scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}
    return scammer_info_data.get(report_key)

def update_report(report_key: str, new_data: dict) -> bool:
    """Update an existing report in Firebase."""
    # Update scammerInfo
    scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}
    
    if report_key not in scammer_info_data:
        return False
        
    # Update the report
    report = scammer_info_data[report_key]
    for field, value in new_data.items():
        if field in report:
            report[field] = value
            
    scammer_info_data[report_key] = report
    firebase_set(SCAMMER_INFO_REF, scammer_info_data)

    # Also update scamReports
    scam_type = report['scam_type']
    identifier = report['identifier']
    scam_type_ref = SCAM_REPORTS_REF.child(scam_type)
    scam_type_data = firebase_get(scam_type_ref) or {}
    
    if identifier in scam_type_data:
        # Find and update the matching report
        for i, r in enumerate(scam_type_data[identifier]):
            if (r['user_id'] == report['user_id'] and 
                r['timestamp'] == report['timestamp']):
                scam_type_data[identifier][i] = report
                firebase_set(scam_type_ref, scam_type_data)
                break
    
    return True

def get_user_reports(user_id: int) -> dict:
    """Get all reports submitted by a user from Firebase."""
    scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}
    user_reports = {}
    
    for key, report in scammer_info_data.items():
        if report.get('user_id') == user_id:
            user_reports[key] = report
            
    return user_reports

def get_all_reports() -> dict:
    """Get all reports in the system from Firebase."""
    return firebase_get(SCAMMER_INFO_REF) or {}

def delete_report(report_key: str) -> bool:
    """Delete a report from Firebase."""
    # Load the report to get details
    scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}
    report = scammer_info_data.get(report_key)
    if not report:
        return False

    # Delete from scamReports
    scam_type = report['scam_type']
    identifier = report['identifier']
    scam_type_ref = SCAM_REPORTS_REF.child(scam_type)
    scam_type_data = firebase_get(scam_type_ref) or {}
    
    if identifier in scam_type_data:
        # Remove all reports for this identifier by this user
        scam_type_data[identifier] = [
            r for r in scam_type_data[identifier] 
            if r['user_id'] != report['user_id']
        ]
        
        # If no more reports, remove identifier
        if not scam_type_data[identifier]:
            del scam_type_data[identifier]
            
        firebase_set(scam_type_ref, scam_type_data)

    # Delete from scammerInfo
    if report_key in scammer_info_data:
        del scammer_info_data[report_key]
        firebase_set(SCAMMER_INFO_REF, scammer_info_data)

    return True

def clear_all_data():
    """Clear all scam data from Firebase."""
    firebase_set(SCAM_REPORTS_REF, {})
    firebase_set(SCAMMER_INFO_REF, {})
    firebase_set(ANALYTICS_REF, analytics_data)  # Reset analytics
    firebase_set(BLACKLIST_REF, {})
    return True

def search_reports(scam_type: str, search_id: str) -> list:
    """Search for reports matching an identifier in Firebase."""
    scam_type_ref = SCAM_REPORTS_REF.child(scam_type)
    scam_type_data = firebase_get(scam_type_ref) or {}
    search_id = search_id.lower().strip()

    # Find all matching identifiers (case-insensitive)
    results = []
    for identifier, reports in scam_type_data.items():
        if search_id in identifier.lower():
            results.extend(reports)

    return results

def is_blacklisted(user_id: int) -> bool:
    """Check if user is blacklisted in Firebase."""
    blacklist = firebase_get(BLACKLIST_REF) or {}
    return str(user_id) in blacklist

def blacklist_user(user_id: int, reason: str = "Violation of terms"):
    """Add user to blacklist in Firebase."""
    blacklist = firebase_get(BLACKLIST_REF) or {}
    blacklist[str(user_id)] = {
        'timestamp': int(time.time()),
        'reason': reason
    }
    firebase_set(BLACKLIST_REF, blacklist)
    return True

def unblacklist_user(user_id: int) -> bool:
    """Remove user from blacklist in Firebase."""
    blacklist = firebase_get(BLACKLIST_REF) or {}
    if str(user_id) in blacklist:
        del blacklist[str(user_id)]
        firebase_set(BLACKLIST_REF, blacklist)
        return True
    return False

def get_top_keywords(n=10) -> list:
    """Get top keywords from analytics."""
    analytics = firebase_get(ANALYTICS_REF) or {}
    keywords = analytics.get('top_keywords', {})
    return Counter(keywords).most_common(n)

def get_active_users() -> list:
    """Get most active users from analytics."""
    analytics = firebase_get(ANALYTICS_REF) or {}
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
            f"Okay, please send me the **{scam_type.upper()}** of the scammer. 📝\n\n"
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
            f"Please send me the **{scam_type.upper()}** you want to check. 🔎"
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
    analytics = firebase_get(ANALYTICS_REF) or {}

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
            f"Got it! Now, please tell me the **story of the scam**. 📝\n\n"
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
        scammer_info_data = firebase_get(SCAMMER_INFO_REF) or {}

        # Find matching reports
        matches = []
        for key, report in scammer_info_data.items():
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
                f"✅ Report for **{state['identifier']}** saved with {len(state.get('proof', []))} proof item(s)!\n"
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
                f"✅ Report for **{state['identifier']}** saved!\n"
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
            f"🚨 **WARNING!** The {state['type'].upper()} `{check_id}` "
            f"has {len(reports)} scam reports! 🚨\n\n"
            f"**Risk Level:** {risk_level}\n\n"
            "**Recent Reports:**\n"
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
            f"✅ The {state['type'].upper()} `{check_id}` has **not** been reported.\n"
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
