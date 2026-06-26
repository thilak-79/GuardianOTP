import os
import re
import json
from pathlib import Path
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters
from openai import OpenAI

# -------------------------
# LOAD ENV VARIABLES
# -------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

# -------------------------
# OPENROUTER SETUP
# -------------------------

client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1"
)

# -------------------------
# URL DETECTION
# -------------------------

def has_url(text):
    return bool(re.search(r'https?://\S+|www\.\S+', text))


def extract_urls(text):
    return re.findall(r'https?://\S+|www\.\S+', text)


# -------------------------
# DEFAULT DATA
# -------------------------

def default_analysis_data():
    return {
        "risk_score": 0,
        "classification": "LOW_RISK",
        "scam_type": "",
        "official_bank_domain_match": False,
        "asks_for_sensitive_info": False,
        "urgency": False,
        "impersonation": False,
        "otp_theft": False,
        "explanation": "",
        "recommendation": ""
    }


def normalize_data(data):
    default = default_analysis_data()

    if not isinstance(data, dict):
        return default

    for key, value in default.items():
        if key not in data:
            data[key] = value

    return data


# -------------------------
# HELPER FUNCTIONS
# -------------------------

def keyword_found(text, keywords):
    text = text.lower()
    return any(word in text for word in keywords)


def safe_get(data, key, default=False):
    value = data.get(key, default)
    return value if isinstance(value, bool) else default


def is_safe_otp_notification(text):
    text = text.lower()

    otp_words = [
        "otp",
        "verification code",
        "login code",
        "sms code",
        "security code",
        "code"
    ]

    safety_phrases = [
        "do not share",
        "don't share",
        "dont share",
        "never share",
        "do not disclose",
        "do not reveal",
        "keep this code private",
        "do not give this code"
    ]

    otp_pattern_found = bool(re.search(r'\b\d{4,8}\b', text))
    has_otp_word = keyword_found(text, otp_words)
    has_safety_phrase = keyword_found(text, safety_phrases)

    return has_otp_word and otp_pattern_found and has_safety_phrase


def asks_to_send_otp(text):
    text = text.lower()

    negative_phrases = [
        "do not share",
        "don't share",
        "dont share",
        "never share",
        "do not disclose",
        "do not reveal",
        "do not give"
    ]

    if keyword_found(text, negative_phrases):
        return False

    otp_words = [
        "otp",
        "verification code",
        "login code",
        "whatsapp code",
        "sms code",
        "security code",
        "one time password",
        "one-time password",
        "code",
        "code eka"
    ]

    request_words = [
        "send",
        "forward",
        "share",
        "tell me",
        "give me",
        "please send",
        "please forward",
        "pass me",
        "send me",
        "ewanna",
        "evanna",
        "karanna"
    ]

    return keyword_found(text, otp_words) and keyword_found(text, request_words)


# -------------------------
# RULE-BASED SECURITY OVERRIDES
# -------------------------

def apply_rule_based_overrides(data, message):
    text = message.lower()

    urgency_keywords = [
        "quickly",
        "immediately",
        "urgent",
        "now",
        "hurry",
        "fast",
        "asap",
        "soon",
        "verify immediately",
        "act now",
        "blocked",
        "suspended"
    ]

    bank_keywords = [
        "bank",
        "account",
        "card",
        "pin",
        "cvv",
        "password",
        "login",
        "suspended",
        "blocked",
        "verify",
        "payment",
        "transaction"
    ]

    reward_keywords = [
        "prize",
        "reward",
        "lottery",
        "winner",
        "gift",
        "free",
        "claim",
        "congratulations"
    ]

    app_install_keywords = [
        "install this app",
        "download app",
        "download this app",
        "download this apk",
        "apk",
        "remote access",
        "anydesk",
        "teamviewer"
    ]

    has_urgency = keyword_found(text, urgency_keywords)
    has_bank_word = keyword_found(text, bank_keywords)
    has_reward_word = keyword_found(text, reward_keywords)
    has_app_install = keyword_found(text, app_install_keywords)

    # Safe OTP notification
    if is_safe_otp_notification(text):
        data["otp_theft"] = False
        data["asks_for_sensitive_info"] = False
        data["urgency"] = False
        data["impersonation"] = False
        data["classification"] = "LOW_RISK"
        data["scam_type"] = "Legitimate OTP notification / safety warning"
        data["safe_otp_notification"] = True

        data["explanation"] = (
            "This message appears to be an OTP notification that warns the user not to share the code. "
            "It does not ask the user to send or forward the OTP."
        )

        data["recommendation"] = (
            "Do not share this OTP with anyone. Only use it inside the official app or website you requested it from."
        )

        return data

    # OTP/code forwarding scam
    if asks_to_send_otp(text):
        data["otp_theft"] = True
        data["asks_for_sensitive_info"] = True
        data["classification"] = "DANGEROUS"
        data["scam_type"] = "WhatsApp OTP theft / account takeover scam"

        data["explanation"] = (
            "The message asks the user to send or forward a verification code. "
            "This is a common account takeover method used to steal WhatsApp, bank, "
            "email, or social media accounts."
        )

        data["recommendation"] = (
            "Do not forward or share any OTP, verification code, or login code. "
            "Contact the person through another trusted method and confirm whether they really sent the message."
        )

    # Urgency detection
    if has_urgency:
        data["urgency"] = True

    # Bank phishing with URL
    if has_bank_word and has_url(message):
        data["impersonation"] = True
        data["asks_for_sensitive_info"] = True

        if not data.get("scam_type") or data.get("scam_type") == "Account suspension":
            data["scam_type"] = "Bank phishing / fake account suspension scam"

    # Bank sensitive-info scam
    if has_bank_word and keyword_found(text, ["otp", "pin", "cvv", "password", "login", "card number"]):
        data["asks_for_sensitive_info"] = True
        data["impersonation"] = True

        if not data.get("scam_type") or data.get("scam_type") == "Phishing":
            data["scam_type"] = "Bank credential theft scam"

    # Reward scam with link
    if has_reward_word and has_url(message):
        data["urgency"] = True
        data["reward_link_scam"] = True

        if not data.get("scam_type") or data.get("scam_type") == "Reward scam":
            data["scam_type"] = "Reward / prize phishing scam"

        if not data.get("explanation"):
            data["explanation"] = (
                "The message promises a reward or prize and asks the user to claim it using a link. "
                "This is a common phishing technique used to collect personal details or redirect users to fake websites."
            )

        if not data.get("recommendation"):
            data["recommendation"] = (
                "Do not click the link or enter personal information. Verify the offer through an official source."
            )

    # Suspicious APK/app installation scam
    if has_app_install:
        data["asks_for_sensitive_info"] = True
        data["impersonation"] = True
        data["app_install_scam"] = True
        data["classification"] = "DANGEROUS"
        data["scam_type"] = "Malicious app installation / bank account takeover scam"

        data["explanation"] = (
            "The message asks the user to download and install an APK or app to unlock a bank account. "
            "Scammers often use fake apps or APK files to steal banking credentials, OTPs, or gain remote access."
        )

        data["recommendation"] = (
            "Do not install the APK or app. Only use your bank's official app from Google Play Store, "
            "Apple App Store, or the bank's official website. Contact the bank directly."
        )

    # Scam type fallback
    if not data.get("scam_type"):
        if data.get("otp_theft"):
            data["scam_type"] = "OTP theft scam"
        elif data.get("impersonation"):
            data["scam_type"] = "Impersonation scam"
        elif data.get("asks_for_sensitive_info"):
            data["scam_type"] = "Sensitive information theft attempt"
        elif has_url(message):
            data["scam_type"] = "Suspicious link message"
        else:
            data["scam_type"] = "No clear scam type detected"

    return data


# -------------------------
# RISK SCORE CALCULATION
# -------------------------

def calculate_risk_score(data, message):
    if data.get("safe_otp_notification") is True:
        return 10

    score = 0

    if safe_get(data, "urgency"):
        score += 20

    if safe_get(data, "impersonation"):
        score += 25

    if safe_get(data, "otp_theft"):
        score += 40

    if safe_get(data, "asks_for_sensitive_info"):
        score += 25

    scam_type = data.get("scam_type", "").lower()

    if "phishing" in scam_type:
        score += 30

    if "otp" in scam_type:
        score += 25

    if "account takeover" in scam_type:
        score += 25

    if "bank" in scam_type:
        score += 20

    if "reward" in scam_type or "prize" in scam_type:
        score += 25

    if "malicious app" in scam_type:
        score += 30

    if has_url(message):
        score += 20

    # Strong overrides
    if safe_get(data, "otp_theft"):
        score = max(score, 85)

    if safe_get(data, "otp_theft") and safe_get(data, "urgency"):
        score = max(score, 90)

    if safe_get(data, "asks_for_sensitive_info") and has_url(message):
        score = max(score, 80)

    if safe_get(data, "impersonation") and safe_get(data, "asks_for_sensitive_info"):
        score = max(score, 75)

    if data.get("reward_link_scam") is True:
        score = max(score, 80)

    if data.get("app_install_scam") is True:
        score = max(score, 85)

    return min(score, 100)


def classify_score(score):
    if score >= 80:
        return "DANGEROUS"
    elif score >= 40:
        return "SUSPICIOUS"
    else:
        return "LOW_RISK"


# -------------------------
# CLEAN AI JSON RESPONSE
# -------------------------

def extract_json(ai_text):
    ai_text = ai_text.strip()

    ai_text = ai_text.replace("```json", "")
    ai_text = ai_text.replace("```", "")
    ai_text = ai_text.strip()

    try:
        return json.loads(ai_text)
    except json.JSONDecodeError:
        pass

    match = re.search(r'\{.*\}', ai_text, re.DOTALL)

    if match:
        return json.loads(match.group())

    raise json.JSONDecodeError("Invalid JSON returned by AI", ai_text, 0)


# -------------------------
# AI ANALYSIS FUNCTION
# -------------------------

def analyze_message(message):
    prompt = f"""
You are GuardianOTP, an AI scam detection assistant for Sri Lankan users.

Analyze this message carefully.

Classify the message as one of:
- LOW_RISK
- SUSPICIOUS
- DANGEROUS

Important rules:
- Never say a message is definitely valid.
- If the message looks safe, say it appears low risk.
- Bank messages asking for OTP, password, PIN, CVV, card details, login, payment, or app installation are dangerous.
- Messages with urgency, fear, threats, account suspension, rewards, or suspicious links are risky.
- OTP messages that say "do not share this code" are usually low risk.
- Messages asking the user to send, share, or forward OTP are dangerous.
- If the message asks for WhatsApp code, login code, verification code, or SMS code, mark otp_theft as true.
- If the message asks to download APK/app for bank/account/security reason, mark it dangerous.
- Scam type must not be empty.
- Explanation and recommendation must not be empty.

Return ONLY valid JSON.

Use this exact JSON format:

{{
  "risk_score": 0,
  "classification": "",
  "scam_type": "",
  "official_bank_domain_match": false,
  "asks_for_sensitive_info": false,
  "urgency": false,
  "impersonation": false,
  "otp_theft": false,
  "explanation": "",
  "recommendation": ""
}}

Message:
\"\"\"{message}\"\"\"
"""

    response = client.chat.completions.create(
        model="openai/gpt-3.5-turbo",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    ai_text = response.choices[0].message.content.strip()
    return extract_json(ai_text)


# -------------------------
# TELEGRAM MESSAGE HANDLER
# -------------------------

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_message = update.message.text

    await update.message.reply_text("🔍 Analyzing message...")

    try:
        # Try AI analysis first
        try:
            data = analyze_message(user_message)
            data = normalize_data(data)
        except Exception as ai_error:
            print("AI analysis failed. Using rule-based fallback.")
            print("AI Error:", ai_error)
            data = default_analysis_data()

        # Always apply rule-based checks
        data = apply_rule_based_overrides(data, user_message)

        # Calculate final risk score
        risk_score = calculate_risk_score(data, user_message)
        classification = classify_score(risk_score)

        data["risk_score"] = risk_score
        data["classification"] = classification

        # Default explanation/recommendation
        if not data.get("explanation"):
            if classification == "LOW_RISK":
                data["explanation"] = (
                    "This message does not appear to contain suspicious links, OTP requests, "
                    "bank threats, prize claims, app installation requests, or requests for sensitive information."
                )
            else:
                data["explanation"] = "This message contains suspicious patterns."

        if not data.get("recommendation"):
            if classification == "LOW_RISK":
                data["recommendation"] = (
                    "No immediate action needed. Stay alert and never share OTPs, passwords, PINs, or CVV numbers."
                )
            else:
                data["recommendation"] = (
                    "Be careful. Do not click links, install apps, or share sensitive information."
                )

        urls = extract_urls(user_message)

        if urls:
            url_section = "\n".join(urls)
        else:
            url_section = "No URL detected."

        reply = f"""
🛡️ GuardianOTP Analysis

Classification: {data.get('classification', 'UNKNOWN')}
Risk Score: {data.get('risk_score', 0)}/100

Scam Type:
{data.get('scam_type', 'No clear scam type detected')}

URLs Detected:
{url_section}

Sensitive Info Requested:
{data.get('asks_for_sensitive_info', False)}

Detected Tactics:
Urgency: {data.get('urgency', False)}
Impersonation: {data.get('impersonation', False)}
OTP Theft: {data.get('otp_theft', False)}

Explanation:
{data.get('explanation')}

Recommendation:
{data.get('recommendation')}
"""

        await update.message.reply_text(reply)

    except Exception as e:
        await update.message.reply_text(
            "⚠️ Sorry, I could not analyze this message properly. Please try again."
        )
        print("Final Error:", e)


# -------------------------
# START BOT
# -------------------------

def main():
    if not TELEGRAM_BOT_TOKEN:
        print("Missing TELEGRAM_BOT_TOKEN in .env file")
        return

    if not OPENROUTER_API_KEY:
        print("Missing OPENROUTER_API_KEY in .env file")
        return

    app = ApplicationBuilder() \
        .token(TELEGRAM_BOT_TOKEN) \
        .build()

    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            handle_message
        )
    )

    print("GuardianOTP Bot Running...")
    app.run_polling()


if __name__ == "__main__":
    main()