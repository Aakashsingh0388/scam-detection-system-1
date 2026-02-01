"""
AI-Assisted Scam & Phishing Detection System
Backend: Flask API with Rule-Based Risk Analysis
AI: Gemini for Explanation Only (NOT for detection)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import requests
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ============================================
# CONFIGURATION
# ============================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# ============================================
# INPUT HANDLER MODULE
# ============================================

def detect_input_type(text):
    """Auto-detect if input is URL, phone number, or message"""
    text = text.strip()
    
    # Check for URL patterns
    url_pattern = r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(com|org|net|xyz|top|click|info|co|in|io|ly|tk|ml|ga|cf|gq|bit\.ly|tinyurl)[^\s]*'
    if re.match(url_pattern, text, re.IGNORECASE):
        return "url"
    
    # Check for phone number patterns (10+ digits, may include country code)
    phone_pattern = r'^[\+]?[0-9\s\-\(\)]{10,}$'
    if re.match(phone_pattern, text.replace(" ", "")):
        return "phone"
    
    # Default to message
    return "message"

def detect_language(text):
    """Detect language: English, Hindi, or Hinglish"""
    # Hindi Unicode range
    hindi_pattern = r'[\u0900-\u097F]'
    hindi_chars = len(re.findall(hindi_pattern, text))
    
    # English pattern
    english_chars = len(re.findall(r'[a-zA-Z]', text))
    
    total = hindi_chars + english_chars
    if total == 0:
        return "english"
    
    if hindi_chars > english_chars:
        return "hindi"
    elif hindi_chars > 0 and english_chars > 0:
        return "hinglish"
    return "english"

def normalize_input(text):
    """Clean and normalize input text"""
    text = text.strip()
    text = re.sub(r'\s+', ' ', text)  # Remove extra whitespace
    return text

def extract_urls_from_text(text):
    """Extract URLs from message text"""
    # include bare domains like example.com as well
    url_pattern = r'https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+|\b[a-z0-9.-]+\.(com|org|net|in|io|co|xyz|top|click|info|ly|tk|ml|ga|cf|gq)\b'
    return re.findall(url_pattern, text, re.IGNORECASE)

def extract_phones_from_text(text):
    """Extract phone numbers from message text"""
    phone_pattern = r'[\+]?[0-9]{10,13}'
    return re.findall(phone_pattern, text.replace(" ", "").replace("-", ""))

# ============================================
# RULE-BASED RISK ANALYZER (CORE LOGIC)
# ============================================

# Message Analysis Rules
MESSAGE_RULES = {
    # Urgency words (high risk)
    "urgency": {
        "patterns": [
            r'\b(urgent|immediately|right now|act now|hurry|last chance|limited time|expires? today|don\'?t delay)\b',
            r'\b(तुरंत|अभी|जल्दी|आखिरी मौका)\b'
        ],
        "weight": 15,
        "flag": "urgency_pressure"
    },
    # OTP/KYC requests
    "otp_kyc": {
        "patterns": [
            r'\b(otp|kyc|verify|verification|cvv|pin|password|पासवर्ड)\b',
            r'\b(share|send|provide|enter).{0,20}(otp|code|pin)\b'
        ],
        "weight": 20,
        "flag": "otp_kyc_request"
    },
    # Account blocked/suspended
    "account_threat": {
        "patterns": [
            r'\b(account|खाता).{0,20}(block|suspend|close|deactivat|बंद|ब्लॉक)\b',
            r'\b(block|suspend|deactivat).{0,20}(account|खाता)\b'
        ],
        "weight": 18,
        "flag": "account_threat"
    },
    # Lottery/reward bait
    "lottery_reward": {
        "patterns": [
            r'\b(congratulations|winner|won|lottery|prize|reward|gift|cash prize|इनाम|जीत)\b',
            r'\b(claim|collect).{0,20}(prize|reward|money)\b',
            r'\b(free|मुफ्त).{0,10}(gift|iphone|laptop|money)\b'
        ],
        "weight": 20,
        "flag": "lottery_reward_bait"
    },
    # Job offer scam
    "job_scam": {
        "patterns": [
            r'\b(earn|income|salary).{0,20}(lakhs?|crores?|per day|daily|weekly)\b',
            r'\b(work from home|wfh).{0,20}(earn|income|money)\b',
            r'\b(no interview|direct joining|immediate joining)\b'
        ],
        "weight": 18,
        "flag": "suspicious_job_offer"
    },
    # Authority impersonation
    "authority": {
        "patterns": [
            r'\b(rbi|reserve bank|income tax|it department|police|cyber cell|sbi|hdfc|icici|axis)\b',
            r'\b(government|सरकार|बैंक).{0,20}(notice|warning|alert)\b'
        ],
        "weight": 15,
        "flag": "authority_impersonation"
    },
    # Money request
    "money_request": {
        "patterns": [
            r'\b(transfer|send|pay).{0,20}(money|amount|rs|₹|rupees)\b',
            r'\b(processing fee|registration fee|advance payment)\b'
        ],
        "weight": 18,
        "flag": "money_request"
    },
    # Poor grammar indicators
    "poor_grammar": {
        "patterns": [
            r'(!!!|\?\?\?|\.\.\.\.+)',
            r'\b(plz|pls|ur|u r|bcoz|coz|dis|dat|dnt)\b'
        ],
        "weight": 8,
        "flag": "poor_grammar"
    },
    # Link in message
    "embedded_link": {
        "patterns": [
            r'https?://[^\s]+',
            r'bit\.ly|tinyurl|short\.link'
        ],
        "weight": 10,
        "flag": "contains_link"
    }
}

# URL Analysis Rules
URL_RULES = {
    # IP-based URL
    "ip_based": {
        "pattern": r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        "weight": 25,
        "flag": "ip_based_url"
    },
    # Suspicious TLDs
    "suspicious_tld": {
        "tlds": ['.xyz', '.top', '.click', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.work', '.loan'],
        "weight": 18,
        "flag": "suspicious_tld"
    },
    # URL shorteners
    "shortener": {
        "domains": ['bit.ly', 'tinyurl.com', 'short.link', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'],
        "weight": 15,
        "flag": "url_shortener"
    },
    # Brand spoofing
    "brand_spoof": {
        "brands": ['google', 'facebook', 'amazon', 'flipkart', 'paytm', 'phonepe', 'gpay', 'sbi', 'hdfc', 'icici', 'axis', 'netflix', 'whatsapp', 'instagram'],
        "weight": 22,
        "flag": "brand_spoofing"
    },
    # Too many subdomains
    "many_subdomains": {
        "threshold": 3,
        "weight": 12,
        "flag": "excessive_subdomains"
    },
    # Very long URL
    "long_url": {
        "threshold": 100,
        "weight": 10,
        "flag": "suspicious_long_url"
    },
    # Random string in URL
    "random_string": {
        "pattern": r'[a-z0-9]{15,}',
        "weight": 12,
        "flag": "random_string_url"
    }
}

# Phone Number Rules
PHONE_RULES = {
    # Country code mismatch (non-Indian number in Indian context)
    "foreign_code": {
        "codes": ['+1', '+44', '+234', '+233', '+254', '+880', '+92'],
        "weight": 15,
        "flag": "foreign_country_code"
    },
    # Invalid pattern
    "invalid_pattern": {
        "weight": 20,
        "flag": "invalid_number_pattern"
    },
    # Too short/long
    "length_issue": {
        "weight": 12,
        "flag": "suspicious_number_length"
    }
}

# Additional heuristics
SUSPICIOUS_PATH_TOKENS = ['verify', 'confirm', 'login', 'secure', 'account', 'update', 'bank', 'payment', 'refund', 'prize', 'claim', 'click', 'authenticate', 'signin', 'token']

def deleet(s: str) -> str:
    """Normalize common leet substitutions to detect lookalikes."""
    return (s.replace('0', 'o').replace('1', 'l').replace('3', 'e')
            .replace('5', 's').replace('4', 'a').replace('7', 't').replace('8', 'b'))


def analyze_message(text):
    """Analyze message text using rule engine"""
    risk_score = 0
    flags = []
    details = []
    
    text_lower = text.lower()
    
    for rule_name, rule_data in MESSAGE_RULES.items():
        for pattern in rule_data["patterns"]:
            if re.search(pattern, text_lower, re.IGNORECASE):
                risk_score += rule_data["weight"]
                if rule_data["flag"] not in flags:
                    flags.append(rule_data["flag"])
                    details.append({
                        "rule": rule_name,
                        "flag": rule_data["flag"],
                        "points": rule_data["weight"]
                    })
                break  # Count each rule only once
    
    # Check for embedded URLs and analyze them
    urls = extract_urls_from_text(text)
    for url in urls[:2]:  # Limit to 2 URLs
        url_result = analyze_url(url)
        risk_score += min(url_result["risk_score"] // 2, 30)  # Add partial URL risk
        flags.extend([f for f in url_result["flags"] if f not in flags])
    
    # Check for embedded phone numbers
    phones = extract_phones_from_text(text)
    for phone in phones[:2]:
        phone_result = analyze_phone(phone)
        risk_score += min(phone_result["risk_score"] // 3, 15)
        flags.extend([f for f in phone_result["flags"] if f not in flags])
    
    return {
        "risk_score": min(risk_score, 100),
        "flags": flags,
        "details": details,
        "embedded_urls": urls,
        "embedded_phones": phones
    }


def analyze_url(url):
    """Analyze URL using rule engine"""
    risk_score = 0
    flags = []
    details = []
    
    url_lower = url.lower()
    
    try:
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        pathname = (parsed.path or '') + (parsed.query and ('?' + parsed.query) or '')
    except:
        domain = url
    
    # IP-based URL check
    if re.search(URL_RULES["ip_based"]["pattern"], url_lower):
        risk_score += URL_RULES["ip_based"]["weight"]
        flags.append(URL_RULES["ip_based"]["flag"])
        details.append({"rule": "ip_based", "points": URL_RULES["ip_based"]["weight"]})

    # Punycode / IDN homograph indicator
    if 'xn--' in domain:
        risk_score += 20
        flags.append('punycode_domain')
        details.append({"rule": "punycode", "points": 20})

    # userinfo '@' in URL (possible phishing)
    if '@' in url_lower:
        risk_score += 18
        flags.append('userinfo_in_url')
        details.append({"rule": "userinfo", "points": 18})

    # HTTP without TLS
    if url_lower.startswith('http://') and not url_lower.startswith('https://'):
        risk_score += 8
        flags.append('no_https')
        details.append({"rule": "no_https", "points": 8})
    
    # Suspicious TLD check
    for tld in URL_RULES["suspicious_tld"]["tlds"]:
        if domain.endswith(tld):
            risk_score += URL_RULES["suspicious_tld"]["weight"]
            flags.append(URL_RULES["suspicious_tld"]["flag"])
            details.append({"rule": "suspicious_tld", "tld": tld, "points": URL_RULES["suspicious_tld"]["weight"]})
            break
    
    # URL shortener check
    for shortener in URL_RULES["shortener"]["domains"]:
        if shortener in domain:
            risk_score += URL_RULES["shortener"]["weight"]
            flags.append(URL_RULES["shortener"]["flag"])
            details.append({"rule": "shortener", "points": URL_RULES["shortener"]["weight"]})
            break
    
    # Brand spoofing check
    # Brand spoofing with leet/translation detection
    for brand in URL_RULES["brand_spoof"]["brands"]:
        bl = brand.lower()
        if bl in domain.lower() or bl in deleet(domain.lower()):
            official_domains = [f'{brand}.com', f'{brand}.in', f'{brand}.co.in', f'{brand}.org']
            is_official = any(domain.endswith(od) or domain == od.replace('www.', '') for od in official_domains)
            if not is_official:
                risk_score += URL_RULES["brand_spoof"]["weight"]
                flags.append(URL_RULES["brand_spoof"]["flag"])
                details.append({"rule": "brand_spoof", "brand": brand, "points": URL_RULES["brand_spoof"]["weight"]})
                break
    
    # Subdomain count check
    subdomain_count = domain.count('.') - 1
    if subdomain_count >= URL_RULES["many_subdomains"]["threshold"]:
        risk_score += URL_RULES["many_subdomains"]["weight"]
        flags.append(URL_RULES["many_subdomains"]["flag"])
        details.append({"rule": "many_subdomains", "count": subdomain_count, "points": URL_RULES["many_subdomains"]["weight"]})
    
    # Long URL check
    if len(url) > URL_RULES["long_url"]["threshold"]:
        risk_score += URL_RULES["long_url"]["weight"]
        flags.append(URL_RULES["long_url"]["flag"])
        details.append({"rule": "long_url", "length": len(url), "points": URL_RULES["long_url"]["weight"]})
    
    # Random string check
    if re.search(URL_RULES["random_string"]["pattern"], url_lower):
        risk_score += URL_RULES["random_string"]["weight"]
        flags.append(URL_RULES["random_string"]["flag"])
        details.append({"rule": "random_string", "points": URL_RULES["random_string"]["weight"]})

    # Suspicious path tokens
    combined = (pathname or '') + ' ' + url_lower
    for token in SUSPICIOUS_PATH_TOKENS:
        if token in combined:
            risk_score += 12
            if 'suspicious_path_token' not in flags:
                flags.append('suspicious_path_token')
                details.append({"rule": "suspicious_path", "points": 12})

    # Minimal domain character oddity check
    if not flags and domain and domain.count('.') >= 1:
        if re.search(r'[^a-z0-9.-]', domain, re.IGNORECASE):
            risk_score += 6
            flags.append('weird_domain_chars')
            details.append({"rule": "weird_chars", "points": 6})
    
    return {
        "risk_score": min(risk_score, 100),
        "flags": flags,
        "details": details,
        "domain": domain
    }


def analyze_phone(phone):
    """Analyze phone number using rule engine"""
    risk_score = 0
    flags = []
    details = []
    
    # Clean the phone number
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Foreign country code check
    for code in PHONE_RULES["foreign_code"]["codes"]:
        if clean_phone.startswith(code):
            risk_score += PHONE_RULES["foreign_code"]["weight"]
            flags.append(PHONE_RULES["foreign_code"]["flag"])
            details.append({"rule": "foreign_code", "code": code, "points": PHONE_RULES["foreign_code"]["weight"]})
            break
    
    # Length validation (Indian numbers: 10 digits, with country code: 12-13)
    digits_only = re.sub(r'\D', '', clean_phone)
    if len(digits_only) < 10 or len(digits_only) > 15:
        risk_score += PHONE_RULES["length_issue"]["weight"]
        flags.append(PHONE_RULES["length_issue"]["flag"])
        details.append({"rule": "length_issue", "length": len(digits_only), "points": PHONE_RULES["length_issue"]["weight"]})
    
    # Invalid pattern for Indian numbers
    if len(digits_only) == 10:
        # Indian mobile numbers start with 6, 7, 8, or 9
        if not digits_only[0] in '6789':
            risk_score += PHONE_RULES["invalid_pattern"]["weight"]
            flags.append(PHONE_RULES["invalid_pattern"]["flag"])
            details.append({"rule": "invalid_pattern", "points": PHONE_RULES["invalid_pattern"]["weight"]})
    
    # Check for repeated digits (like 9999999999)
    if len(set(digits_only[-10:])) <= 2:
        risk_score += 15
        flags.append("suspicious_repeated_digits")
        details.append({"rule": "repeated_digits", "points": 15})

    # Long repeated sequences anywhere (e.g., 9999999)
    if re.search(r'(\d)\1{4,}', digits_only):
        if "suspicious_repeated_digits" not in flags:
            risk_score += 12
            flags.append("suspicious_repeated_digits")
            details.append({"rule": "repeated_sequence", "points": 12})
    
    return {
        "risk_score": min(risk_score, 100),
        "flags": flags,
        "details": details,
        "cleaned_number": clean_phone
    }


# ============================================
# RISK SCORING ENGINE
# ============================================

def calculate_risk_level(score):
    """
    Calculate risk level from score.
    0-30: Safe
    31-60: Suspicious
    61-100: High Risk / Scam
    """
    if score <= 30:
        return "safe"
    elif score <= 60:
        return "suspicious"
    else:
        return "high_risk"


# ============================================
# AI EXPLANATION LAYER (GEMINI)
# ============================================

def get_gemini_explanation(input_type, risk_score, flags, language):
    """
    Get AI explanation from Gemini.
    AI does NOT decide risk - it only explains the rule-based findings.
    """
    if not GEMINI_API_KEY:
        return generate_fallback_explanation(input_type, risk_score, flags, language)
    
    # Compressed JSON payload for minimal token usage
    analysis_data = {
        "input_type": input_type,
        "risk_score": risk_score,
        "risk_level": calculate_risk_level(risk_score),
        "flags": flags,
        "language": language
    }
    
    # Construct the prompt
    prompt = f"""You are a cybersecurity assistant explaining scam detection results to users.
The detection was done by a RULE-BASED system, NOT by AI. Your job is ONLY to explain.

Analysis Data: {analysis_data}

Provide a brief explanation (3-5 lines) that includes:
1. Why this is flagged as {calculate_risk_level(risk_score)} based on the detected patterns
2. What the user should NOT do
3. Safe next steps

Keep response simple and helpful. Use {language} language if not English.
Do NOT make new assessments - only explain the rule findings."""

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 200
                }
            },
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            return result["candidates"][0]["content"]["parts"][0]["text"]
        else:
            return generate_fallback_explanation(input_type, risk_score, flags, language)
            
    except Exception as e:
        print(f"Gemini API error: {e}")
        return generate_fallback_explanation(input_type, risk_score, flags, language)


def generate_fallback_explanation(input_type, risk_score, flags, language):
    """Generate explanation without AI when Gemini is unavailable"""
    
    flag_explanations = {
        "urgency_pressure": "Contains urgent language designed to pressure quick decisions",
        "otp_kyc_request": "Requests sensitive information like OTP or KYC details",
        "account_threat": "Threatens account suspension or blocking",
        "lottery_reward_bait": "Promises prizes, rewards, or lottery winnings",
        "suspicious_job_offer": "Offers suspicious job with unrealistic earnings",
        "authority_impersonation": "May be impersonating banks or government",
        "money_request": "Requests money transfer or payment",
        "poor_grammar": "Contains suspicious grammar patterns",
        "contains_link": "Contains links that need verification",
        "ip_based_url": "URL uses IP address instead of domain name",
        "suspicious_tld": "Uses suspicious domain extension",
        "url_shortener": "Uses URL shortener to hide actual destination",
        "brand_spoofing": "May be impersonating a known brand",
        "excessive_subdomains": "Has suspicious number of subdomains",
        "suspicious_long_url": "Unusually long URL",
        "random_string_url": "Contains random characters in URL",
        "foreign_country_code": "Phone number from foreign country",
        "invalid_number_pattern": "Invalid phone number pattern",
        "suspicious_number_length": "Suspicious phone number length",
        "suspicious_repeated_digits": "Phone has suspicious repeated digits"
    }
    
    risk_level = calculate_risk_level(risk_score)
    
    explanation_parts = []
    
    if risk_level == "high_risk":
        explanation_parts.append("⚠️ HIGH RISK: This appears to be a potential scam.")
    elif risk_level == "suspicious":
        explanation_parts.append("⚡ SUSPICIOUS: This has some concerning patterns.")
    else:
        explanation_parts.append("✅ LOW RISK: No major red flags detected.")
    
    # Add flag explanations
    if flags:
        explanation_parts.append("Detected issues: " + "; ".join([
            flag_explanations.get(f, f.replace("_", " ")) for f in flags[:3]
        ]))
    
    # Safety recommendations
    if risk_level in ["high_risk", "suspicious"]:
        explanation_parts.append("Do NOT click links, share OTP, or send money. Verify through official channels.")
    
    return " ".join(explanation_parts)


# ============================================
# MAIN API ENDPOINT
# ============================================

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint.
    Accepts: { "input": "text to analyze", "type": "auto|message|url|phone" }
    Returns: Risk analysis with AI explanation
    """
    try:
        data = request.get_json()
        
        if not data or 'input' not in data:
            return jsonify({"error": "No input provided"}), 400
        
        user_input = normalize_input(data.get('input', ''))
        input_type = data.get('type', 'auto')
        
        if not user_input:
            return jsonify({"error": "Empty input"}), 400
        
        # Auto-detect input type if not specified
        if input_type == 'auto':
            input_type = detect_input_type(user_input)
        
        # Detect language
        language = detect_language(user_input)
        
        # Run appropriate analyzer
        if input_type == 'url':
            analysis = analyze_url(user_input)
        elif input_type == 'phone':
            analysis = analyze_phone(user_input)
        else:
            analysis = analyze_message(user_input)
        
        risk_score = analysis["risk_score"]
        flags = analysis["flags"]
        risk_level = calculate_risk_level(risk_score)
        
        # Get AI explanation (does NOT affect risk score)
        explanation = get_gemini_explanation(input_type, risk_score, flags, language)
        
        # Build response
        response = {
            "success": True,
            "input_type": input_type,
            "language": language,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "details": analysis.get("details", []),
            "explanation": explanation,
            "disclaimer": "This is a risk-based analysis, not a verification. Always verify through official channels."
        }
        
        # Add embedded URLs/phones for messages
        if input_type == "message":
            response["embedded_urls"] = analysis.get("embedded_urls", [])
            response["embedded_phones"] = analysis.get("embedded_phones", [])
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Scam Detection API",
        "gemini_configured": bool(GEMINI_API_KEY)
    })


@app.route('/')
def index():
    """Serve the frontend"""
    return app.send_static_file('index.html')


# ============================================
# RUN SERVER
# ============================================

if __name__ == '__main__':
    print("=" * 50)
    print("🛡️ AI-Assisted Scam Detection System")
    print("=" * 50)
    print(f"Gemini API: {'Configured' if GEMINI_API_KEY else 'Not configured (using fallback)'}")
    print("Starting server on http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
