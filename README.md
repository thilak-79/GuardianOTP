# GuardianOTP

**GuardianOTP** is an AI-powered Telegram bot that helps users detect OTP theft, phishing messages, fake bank alerts, reward scams, and malicious app installation attempts.

The system is designed for Sri Lankan users who receive suspicious messages through SMS, WhatsApp, Telegram, or other messaging platforms. Users can forward or paste a suspicious message into the bot, and GuardianOTP returns a risk score, scam classification, explanation, and safety recommendation.

---

## Problem

Scammers often trick users into sharing sensitive information such as OTP codes, bank credentials, PIN numbers, CVV numbers, passwords, or login details.

Common scam examples include:

* “Your bank account has been suspended. Verify now.”
* “Can you forward the WhatsApp code quickly?”
* “Congratulations! You won Rs. 50,000. Claim your prize.”
* “Install this APK to unlock your bank account.”

Many users cannot easily identify whether these messages are safe, suspicious, or dangerous. GuardianOTP helps users make safer decisions before clicking links, sharing OTPs, or installing fake apps.

---

## Solution

GuardianOTP analyzes suspicious messages using a hybrid detection approach:

1. **AI-Based Analysis**
   The message is analyzed using an AI model through the OpenRouter API.

2. **Rule-Based Security Checks**
   Python rules detect high-risk scam patterns such as OTP forwarding, bank phishing, fake rewards, malicious APK requests, urgency, impersonation, and sensitive information requests.

3. **Risk Score Calculation**
   The system calculates a final risk score from 0 to 100.

4. **Telegram Bot Response**
   The bot sends a clear explanation and recommendation to the user.

---

## Current Features

* Detects OTP theft attempts
* Detects WhatsApp account takeover scams
* Detects bank phishing messages
* Detects fake account suspension messages
* Detects reward and prize scams
* Detects malicious APK/app installation scams
* Detects suspicious URLs
* Detects urgency and impersonation
* Distinguishes safe OTP notifications from OTP theft attempts
* Provides risk score from 0 to 100
* Provides plain-language explanation
* Provides safety recommendation
* Includes fallback rule-based detection if AI analysis fails

---

## Example Output

```text
🛡️ GuardianOTP Analysis

Classification: DANGEROUS
Risk Score: 100/100

Scam Type:
WhatsApp OTP theft / account takeover scam

URLs Detected:
No URL detected.

Sensitive Info Requested:
True

Detected Tactics:
Urgency: True
Impersonation: False
OTP Theft: True

Explanation:
The message asks the user to send or forward a verification code. This is a common account takeover method used to steal WhatsApp, bank, email, or social media accounts.

Recommendation:
Do not forward or share any OTP, verification code, or login code. Contact the person through another trusted method and confirm whether they really sent the message.
```

---

## Tech Stack

* Python
* Telegram Bot API
* python-telegram-bot
* OpenRouter API
* OpenAI Python SDK
* python-dotenv
* Regular expressions for URL and keyword detection

---

## Project Structure

```text
guardianotp/
├── telegram_bot.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/thilak-79/GuardianOTP.git
cd GuardianOTP
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Virtual Environment

For Windows PowerShell:

```powershell
.\.venv\Scripts\activate
```

For Linux/macOS:

```bash
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Create Environment File

Create a `.env` file in the project folder.

```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
OPENROUTER_API_KEY=your_openrouter_api_key_here
```

Do not commit the `.env` file to GitHub.

### 6. Run the Bot

```bash
python telegram_bot.py
```

If the bot starts successfully, you should see:

```text
GuardianOTP Bot Running...
```

Then open Telegram, start your bot, and send a suspicious message for analysis.

---

## Test Messages

### OTP Theft Scam

```text
Hi machan, I accidentally sent my WhatsApp code to your number. Can you forward it quickly please?
```

Expected result:

```text
Classification: DANGEROUS
OTP Theft: True
```

### Safe OTP Notification

```text
Your OTP is 482193. Do not share this code with anyone.
```

Expected result:

```text
Classification: LOW_RISK
OTP Theft: False
```

### Bank Phishing

```text
Your bank account has been suspended. Verify now: http://fake-bank-login.com
```

Expected result:

```text
Classification: DANGEROUS
Impersonation: True
Urgency: True
```

### Reward Scam

```text
Congratulations! You won Rs. 50,000. Claim your prize here: www.reward-lk.com
```

Expected result:

```text
Classification: DANGEROUS
Scam Type: Reward / prize phishing scam
```

### Malicious APK Scam

```text
To unlock your bank account, download this APK and install this app immediately.
```

Expected result:

```text
Classification: DANGEROUS
Scam Type: Malicious app installation / bank account takeover scam
```

---

## Privacy and Security

GuardianOTP is designed as a user-initiated system. The bot only analyzes messages that users choose to send.

Important security practices:

* Do not share real OTPs, passwords, PINs, CVVs, or bank credentials.
* API keys are stored in `.env`.
* `.env` is ignored using `.gitignore`.
* Sensitive values should be masked before storing logs in future versions.
* The bot provides warnings and recommendations but does not replace official bank or cybersecurity support.

---

## Limitations

The current version is an MVP. It may not detect every scam message, especially highly obfuscated or newly emerging scam patterns.

Current limitations:

* No real-time WhatsApp/SMS interception
* No VirusTotal integration yet
* No Google Safe Browsing integration yet
* No APK file scanning yet
* No Sinhala/Tamil full-language output yet
* No production database or dashboard yet
* AI API availability depends on OpenRouter

---

## Future Improvements

Planned improvements include:

* VirusTotal URL scanning
* Google Safe Browsing integration
* APK/file reputation checking
* Sinhala and Tamil warning messages
* FastAPI backend
* SQLite scan-result logging without message content
* Privacy masking for OTPs and card numbers
* Prompt injection detection
* URL lookalike and Unicode homoglyph detection
* User feedback collection
* Evaluation using accuracy, precision, recall, and F1-score
* Cloud deployment using Railway or Render

---

## Team

GuardianOTP was developed as part of the Aurora ENG2.0 project.

---

## Disclaimer

GuardianOTP is an educational cybersecurity project. It helps identify suspicious messages and provides safety recommendations, but users should always verify sensitive issues directly through official bank, government, or service-provider channels.
