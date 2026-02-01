# 🛡️ ScamShield AI - Scam & Phishing Detection System

> "Not just detecting scams — explaining them."

## Overview

A real-time, explainable, low-cost scam detection web application that analyzes:
- **Text Messages** (SMS / WhatsApp / Email)
- **Website URLs / Links**
- **Phone Numbers**

### Core Design Principle

```
❌ AI does NOT decide scam or safe
✅ Backend rule engine decides risk
🧠 Gemini AI ONLY explains why something is risky
```

**AI is a reasoning assistant, NOT a verification authority.**

---

## Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Set Gemini API Key (Optional)

Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)

```bash
# Linux/Mac
export GEMINI_API_KEY="your-api-key-here"

# Windows CMD
set GEMINI_API_KEY=your-api-key-here

# Windows PowerShell
$env:GEMINI_API_KEY="your-api-key-here"
```

> **Note:** The app works without Gemini API key using built-in fallback explanations.

### 3. Run the Server

```bash
python app.py
```

### 4. Open in Browser

Navigate to: `http://localhost:5000`

---

## Project Structure

```
backend/
├── app.py              # Flask backend with rule-based analyzer
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── static/
    ├── index.html      # Frontend HTML
    ├── style.css       # Styles
    └── script.js       # Frontend JavaScript
```

---

## API Endpoint

### POST `/api/analyze`

**Request:**
```json
{
  "input": "Your suspicious text, URL, or phone number",
  "type": "auto | message | url | phone"
}
```

**Response:**
```json
{
  "success": true,
  "input_type": "message",
  "language": "english",
  "risk_score": 82,
  "risk_level": "high_risk",
  "flags": ["urgency_pressure", "otp_kyc_request", "lottery_reward_bait"],
  "details": [...],
  "explanation": "AI-generated explanation of the risk",
  "disclaimer": "This is a risk-based analysis..."
}
```

---

## Risk Scoring

| Score Range | Risk Level | Meaning |
|-------------|------------|---------|
| 0-30 | Safe | No major red flags detected |
| 31-60 | Suspicious | Some concerning patterns |
| 61-100 | High Risk | Likely a scam |

---

## Detection Rules

### Message Rules
- Urgency words (urgent, immediately, last chance)
- OTP / KYC requests
- Account blocked/suspended threats
- Lottery / reward bait
- Suspicious job offers
- Authority impersonation
- Money transfer requests
- Poor grammar patterns

### URL Rules
- IP-based URLs
- Suspicious TLDs (.xyz, .top, .click)
- URL shorteners (bit.ly, tinyurl)
- Brand spoofing detection
- Excessive subdomains
- Random string patterns

### Phone Rules
- Foreign country code detection
- Invalid number patterns
- Suspicious length
- Repeated digit patterns

---

## Gemini API Prompt

The exact prompt sent to Gemini:

```
You are a cybersecurity assistant explaining scam detection results to users.
The detection was done by a RULE-BASED system, NOT by AI. Your job is ONLY to explain.

Analysis Data: {
  "input_type": "message | url | phone",
  "risk_score": 82,
  "risk_level": "high_risk | suspicious | safe",
  "flags": ["urgency", "otp_request", "suspicious_link"],
  "language": "english"
}

Provide a brief explanation (3-5 lines) that includes:
1. Why this is flagged based on the detected patterns
2. What the user should NOT do
3. Safe next steps

Keep response simple and helpful.
Do NOT make new assessments - only explain the rule findings.
```

---

## Privacy & Ethics

- ✅ **No data storage** - Input is processed and discarded
- ✅ **No logging** - We don't log your messages
- ✅ **No verification claims** - We provide risk-based analysis only
- ✅ **Transparent** - AI explains, doesn't decide

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python Flask |
| Frontend | HTML, CSS, JavaScript |
| AI | Google Gemini API (Free Tier) |
| Database | None (Stateless) |

---

## Hackathon Demo

This is a hackathon demonstration project. It prioritizes:
- ✅ Clarity
- ✅ Stability  
- ✅ Honesty
- ❌ No fake claims
- ❌ No hallucinated features

---

## License

MIT License - Built for educational and demonstration purposes.
