/**
 * ScamShield AI - Rule-Based Scam Analyzer
 * Core detection logic - AI does NOT decide, rules do.
 */

// ============================================
// TYPES
// ============================================

export interface AnalysisResult {
  riskScore: number
  riskLevel: 'safe' | 'suspicious' | 'high_risk'
  flags: string[]
  details: Array<{ rule: string; flag: string; points: number }>
  embeddedUrls?: string[]
  embeddedPhones?: string[]
}

export interface FullAnalysisResult extends AnalysisResult {
  inputType: 'message' | 'url' | 'phone'
  language: 'english' | 'hindi' | 'hinglish'
  explanation: string
  disclaimer: string
}

// ============================================
// INPUT HANDLER
// ============================================

export function detectInputType(text: string): 'message' | 'url' | 'phone' {
  const trimmed = text.trim()
  
  // URL patterns
  const urlPattern = /^https?:\/\/[^\s]+|^www\.[^\s]+|^[a-zA-Z0-9-]+\.(com|org|net|xyz|top|click|info|co|in|io|ly|tk|ml|ga|cf|gq|bit\.ly|tinyurl)/i
  if (urlPattern.test(trimmed)) {
    return 'url'
  }
  
  // Phone pattern (10+ digits with optional country code)
  const phonePattern = /^[+]?[0-9\s\-()]{10,}$/
  if (phonePattern.test(trimmed.replace(/\s/g, ''))) {
    return 'phone'
  }
  
  return 'message'
}

export function detectLanguage(text: string): 'english' | 'hindi' | 'hinglish' {
  const hindiPattern = /[\u0900-\u097F]/g
  const hindiChars = (text.match(hindiPattern) || []).length
  const englishChars = (text.match(/[a-zA-Z]/g) || []).length
  
  const total = hindiChars + englishChars
  if (total === 0) return 'english'
  
  if (hindiChars > englishChars) return 'hindi'
  if (hindiChars > 0 && englishChars > 0) return 'hinglish'
  return 'english'
}

export function normalizeInput(text: string): string {
  return text.trim().replace(/\s+/g, ' ')
}

export function extractUrls(text: string): string[] {
  // capture common URL forms including bare domains like example.com
  const urlPattern = /https?:\/\/[^\s]+|www\.[^\s]+|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+|\b[a-z0-9.-]+\.(com|org|net|in|io|co|xyz|top|click|info|ly|tk|ml|ga|cf|gq)\b/gi
  return text.match(urlPattern) || []
}

export function extractPhones(text: string): string[] {
  const phonePattern = /[+]?[0-9]{10,13}/g
  const cleaned = text.replace(/[\s\-]/g, '')
  return cleaned.match(phonePattern) || []
}

// ============================================
// MESSAGE ANALYSIS RULES
// ============================================

interface Rule {
  patterns: RegExp[]
  weight: number
  flag: string
}

const MESSAGE_RULES: Record<string, Rule> = {
  urgency: {
    patterns: [
      /\b(urgent|immediately|right now|act now|hurry|last chance|limited time|expires? today|don'?t delay|final notice|final warning|within 24 hours?|within 2 hours?|action required)\b/i,
      /\b(तुरंत|अभी|जल्दी|आखिरी मौका|अंतिम चेतावनी|24 घंटे में)\b/i,
      /\b(jaldi|abhi|turant|fauran)\b/i
    ],
    weight: 18,
    flag: 'urgency_pressure'
  },
  otp_kyc: {
    patterns: [
      /\b(otp|kyc|verify|verification|cvv|pin|password|atm pin|upi pin|पासवर्ड)\b/i,
      /\b(share|send|provide|enter|batao|bhejo).{0,20}(otp|code|pin)\b/i,
      /\b(update|complete).{0,15}(kyc|pan|aadhar|aadhaar)\b/i,
      /otp.{0,10}(hai|is|send|bhej)/i
    ],
    weight: 25,
    flag: 'otp_kyc_request'
  },
  account_threat: {
    patterns: [
      /\b(account|खाता|a\/c).{0,20}(block|suspend|close|deactivat|freeze|बंद|ब्लॉक|hold)\b/i,
      /\b(block|suspend|deactivat|freeze).{0,20}(account|खाता|a\/c)\b/i,
      /\b(service|card|upi).{0,15}(block|suspend|stop)\b/i,
      /\b(legal action|कानूनी कार्रवाई|police complaint)\b/i
    ],
    weight: 22,
    flag: 'account_threat'
  },
  lottery_reward: {
    patterns: [
      /\b(congratulations|congrats|winner|won|lottery|prize|reward|gift|cash prize|इनाम|जीत|badhai|mubarak)\b/i,
      /\b(claim|collect|receive).{0,20}(prize|reward|money|amount)\b/i,
      /\b(free|मुफ्त|muft).{0,10}(gift|iphone|laptop|money|car|bike)\b/i,
      /\b(lucky draw|spin wheel|scratch card)\b/i,
      /\b(selected|chosen).{0,15}(winner|prize)\b/i,
      /₹\s*\d{1,3}(,\d{3})*\s*(lakh|crore|cr|lac)/i
    ],
    weight: 25,
    flag: 'lottery_reward_bait'
  },
  job_scam: {
    patterns: [
      /\b(earn|income|salary|kamai|kamao).{0,20}(lakhs?|crores?|per day|daily|weekly|monthly|ghar baithe)\b/i,
      /\b(work from home|wfh|ghar se kaam).{0,20}(earn|income|money|kamai)\b/i,
      /\b(no interview|direct joining|immediate joining|part time job|typing job)\b/i,
      /\b(amazon|flipkart|meesho).{0,15}(job|work|partner)\b/i,
      /\bdata entry.{0,10}(job|work|earn)/i
    ],
    weight: 22,
    flag: 'suspicious_job_offer'
  },
  authority: {
    patterns: [
      /\b(rbi|reserve bank|income tax|it department|police|cyber cell|customs|ed|cbi|enforcement)\b/i,
      /\b(sbi|hdfc|icici|axis|kotak|pnb|bob|canara|union bank|paytm|phonepe|gpay|google pay)\b/i,
      /\b(government|सरकार|बैंक|ministry).{0,20}(notice|warning|alert|message)\b/i,
      /\b(customer care|helpline|support).{0,10}(number|no\.?)\b/i
    ],
    weight: 18,
    flag: 'authority_impersonation'
  },
  money_request: {
    patterns: [
      /\b(transfer|send|pay|bhejo|de do).{0,20}(money|amount|rs|₹|rupees|paisa|paise)\b/i,
      /\b(processing fee|registration fee|advance payment|token money|booking amount)\b/i,
      /\b(pay|deposit).{0,15}(first|only|just).{0,10}(rs|₹|\d)/i,
      /\b(refund|cashback).{0,20}(pending|stuck|process)\b/i,
      /upi.{0,10}(id|address|transfer)/i
    ],
    weight: 22,
    flag: 'money_request'
  },
  poor_grammar: {
    patterns: [
      /(!!!|\?\?\?|\.\.\.\.+)/,
      /\b(plz|pls|ur|u r|bcoz|coz|dis|dat|dnt|2day|2morrow|4u|asap)\b/i,
      /dear\s+(customer|user|sir|madam|member)/i
    ],
    weight: 10,
    flag: 'poor_grammar'
  },
  embedded_link: {
    patterns: [
      /https?:\/\/[^\s]+/i,
      /bit\.ly|tinyurl|short\.link|t\.co|goo\.gl/i,
      /click\s+(here|now|below|link)/i
    ],
    weight: 12,
    flag: 'contains_link'
  },
  delivery_scam: {
    patterns: [
      /\b(delivery|courier|parcel|package|shipment).{0,20}(failed|pending|hold|stuck|address)\b/i,
      /\b(bluedart|delhivery|dtdc|fedex|ecom express|india post).{0,15}(track|delivery)\b/i,
      /track.{0,10}(order|shipment|parcel)/i
    ],
    weight: 18,
    flag: 'delivery_scam'
  },
  loan_scam: {
    patterns: [
      /\b(instant loan|personal loan|loan approved|pre.?approved loan)\b/i,
      /\b(loan).{0,15}(₹|rs|lakh|crore)\b/i,
      /\b(no document|without document|bina document)\b/i,
      /\b(low interest|0% interest|zero interest)\b/i
    ],
    weight: 20,
    flag: 'loan_scam'
  },
  investment_scam: {
    patterns: [
      /\b(invest|trading|crypto|bitcoin|stock).{0,15}(earn|return|profit|double)\b/i,
      /\b(double|triple).{0,10}(money|investment|amount)\b/i,
      /\b(guaranteed|100%|assured).{0,10}(return|profit)\b/i,
      /\b(forex|binary option|mlm|network marketing)\b/i
    ],
    weight: 25,
    flag: 'investment_scam'
  },
  whatsapp_forward: {
    patterns: [
      /\b(forward|share).{0,15}(10|20|100|groups?|contacts?|friends?)\b/i,
      /\b(whatsapp|telegram).{0,10}(forward|share)\b/i,
      /\b(viral|trending|breaking).{0,10}(news|alert)\b/i
    ],
    weight: 12,
    flag: 'chain_message'
  }
}

// ============================================
// URL ANALYSIS RULES
// ============================================

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.work', '.loan']
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'short.link', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
const KNOWN_BRANDS = ['google', 'facebook', 'amazon', 'flipkart', 'paytm', 'phonepe', 'gpay', 'sbi', 'hdfc', 'icici', 'axis', 'netflix', 'whatsapp', 'instagram']

const SUSPICIOUS_PATH_TOKENS = ['verify', 'confirm', 'login', 'secure', 'account', 'update', 'bank', 'payment', 'refund', 'prize', 'claim', 'click', 'authenticate', 'signin', 'token']

function deleet(s: string) {
  return s
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/4/g, 'a')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
}

// ============================================
// PHONE RULES
// ============================================

const FOREIGN_CODES = ['+1', '+44', '+234', '+233', '+254', '+880', '+92']

// ============================================
// ANALYZERS
// ============================================

export function analyzeMessage(text: string): AnalysisResult {
  let riskScore = 0
  const flags: string[] = []
  const details: Array<{ rule: string; flag: string; points: number }> = []
  
  const textLower = text.toLowerCase()
  
  for (const [ruleName, rule] of Object.entries(MESSAGE_RULES)) {
    for (const pattern of rule.patterns) {
      if (pattern.test(textLower)) {
        riskScore += rule.weight
        if (!flags.includes(rule.flag)) {
          flags.push(rule.flag)
          details.push({ rule: ruleName, flag: rule.flag, points: rule.weight })
        }
        break
      }
    }
  }
  
  // Check embedded URLs
  const urls = extractUrls(text)
  for (const url of urls.slice(0, 2)) {
    const urlResult = analyzeUrl(url)
    riskScore += Math.min(Math.floor(urlResult.riskScore / 2), 30)
    for (const flag of urlResult.flags) {
      if (!flags.includes(flag)) flags.push(flag)
    }
  }
  
  // Check embedded phones
  const phones = extractPhones(text)
  for (const phone of phones.slice(0, 2)) {
    const phoneResult = analyzePhone(phone)
    riskScore += Math.min(Math.floor(phoneResult.riskScore / 3), 15)
    for (const flag of phoneResult.flags) {
      if (!flags.includes(flag)) flags.push(flag)
    }
  }
  
  return {
    riskScore: Math.min(riskScore, 100),
    riskLevel: calculateRiskLevel(Math.min(riskScore, 100)),
    flags,
    details,
    embeddedUrls: urls,
    embeddedPhones: phones
  }
}

export function analyzeUrl(url: string): AnalysisResult {
  let riskScore = 0
  const flags: string[] = []
  const details: Array<{ rule: string; flag: string; points: number }> = []
  
  const urlLower = url.toLowerCase()
  
  // Extract domain
  let domain = ''
  let pathname = ''
  try {
    const parsed = new URL(url.startsWith('http') ? url : `http://${url}`)
    domain = parsed.hostname
    pathname = parsed.pathname + (parsed.search || '')
  } catch {
    domain = url.split('/')[0]
  }
  
  // IP-based URL
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlLower)) {
    riskScore += 25
    flags.push('ip_based_url')
    details.push({ rule: 'ip_based', flag: 'ip_based_url', points: 25 })
  }
  
  // Punycode / IDN homograph indicator
  if (domain.includes('xn--')) {
    riskScore += 20
    flags.push('punycode_domain')
    details.push({ rule: 'punycode', flag: 'punycode_domain', points: 20 })
  }

  // '@' in URL (userinfo used to phish)
  if (/@/.test(urlLower)) {
    riskScore += 18
    flags.push('userinfo_in_url')
    details.push({ rule: 'userinfo', flag: 'userinfo_in_url', points: 18 })
  }

  // HTTP without TLS
  if (urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    riskScore += 8
    flags.push('no_https')
    details.push({ rule: 'no_https', flag: 'no_https', points: 8 })
  }
  
  // Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (domain.endsWith(tld)) {
      riskScore += 18
      flags.push('suspicious_tld')
      details.push({ rule: 'suspicious_tld', flag: 'suspicious_tld', points: 18 })
      break
    }
  }
  
  // URL shortener
  for (const shortener of URL_SHORTENERS) {
    if (domain.includes(shortener)) {
      riskScore += 15
      flags.push('url_shortener')
      details.push({ rule: 'shortener', flag: 'url_shortener', points: 15 })
      break
    }
  }
  
  // Brand spoofing: check for leet/lookalike occurrences and tokens
  for (const brand of KNOWN_BRANDS) {
    const brandLower = brand.toLowerCase()
    if (domain.includes(brandLower) || deleet(domain).includes(brandLower)) {
      const officialDomains = [`${brand}.com`, `${brand}.in`, `${brand}.co.in`, `${brand}.org`]
      const isOfficial = officialDomains.some(od => domain.endsWith(od) || domain === od)
      if (!isOfficial) {
        riskScore += 22
        flags.push('brand_spoofing')
        details.push({ rule: 'brand_spoof', flag: 'brand_spoofing', points: 22 })
        break
      }
    }
  }

  // Suspicious path tokens (e.g., /verify, /login)
  const combinedPath = (pathname || '') + ' ' + urlLower
  for (const token of SUSPICIOUS_PATH_TOKENS) {
    if (combinedPath.includes(token)) {
      riskScore += 12
      if (!flags.includes('suspicious_path_token')) {
        flags.push('suspicious_path_token')
        details.push({ rule: 'suspicious_path', flag: 'suspicious_path_token', points: 12 })
      }
    }
  }
  
  // Subdomain count
  const subdomainCount = domain.split('.').length - 2
  if (subdomainCount >= 3) {
    riskScore += 12
    flags.push('excessive_subdomains')
    details.push({ rule: 'many_subdomains', flag: 'excessive_subdomains', points: 12 })
  }
  
  // Long URL
  if (url.length > 100) {
    riskScore += 10
    flags.push('suspicious_long_url')
    details.push({ rule: 'long_url', flag: 'suspicious_long_url', points: 10 })
  }
  
  // Random string
  if (/[a-z0-9]{15,}/.test(urlLower)) {
    riskScore += 12
    flags.push('random_string_url')
    details.push({ rule: 'random_string', flag: 'random_string_url', points: 12 })
  }

  // If no flags added yet and domain looks too short/common, give minimal caution
  if (flags.length === 0 && domain && domain.split('.').length >= 2) {
    // some protective scoring for suspicious constructs
    if (/[^a-z0-9.-]/i.test(domain)) {
      riskScore += 6
      flags.push('weird_domain_chars')
      details.push({ rule: 'weird_chars', flag: 'weird_domain_chars', points: 6 })
    }
  }
  
  return {
    riskScore: Math.min(riskScore, 100),
    riskLevel: calculateRiskLevel(Math.min(riskScore, 100)),
    flags,
    details
  }
}

export function analyzePhone(phone: string): AnalysisResult {
  let riskScore = 0
  const flags: string[] = []
  const details: Array<{ rule: string; flag: string; points: number }> = []
  
  const cleanPhone = phone.replace(/[\s\-()]/g, '')
  
  // Foreign country code
  for (const code of FOREIGN_CODES) {
    if (cleanPhone.startsWith(code)) {
      riskScore += 15
      flags.push('foreign_country_code')
      details.push({ rule: 'foreign_code', flag: 'foreign_country_code', points: 15 })
      break
    }
  }
  
  // Length validation
  const digitsOnly = cleanPhone.replace(/\D/g, '')
  if (digitsOnly.length < 10 || digitsOnly.length > 15) {
    riskScore += 12
    flags.push('suspicious_number_length')
    details.push({ rule: 'length_issue', flag: 'suspicious_number_length', points: 12 })
  }
  
  // Invalid Indian pattern
  if (digitsOnly.length === 10 && !['6', '7', '8', '9'].includes(digitsOnly[0])) {
    riskScore += 20
    flags.push('invalid_number_pattern')
    details.push({ rule: 'invalid_pattern', flag: 'invalid_number_pattern', points: 20 })
  }
  
  // Repeated digits
  const lastTen = digitsOnly.slice(-10)
  if (new Set(lastTen).size <= 2) {
    riskScore += 15
    flags.push('suspicious_repeated_digits')
    details.push({ rule: 'repeated_digits', flag: 'suspicious_repeated_digits', points: 15 })
  }

  // Long repeated sequences anywhere (e.g., 9999999)
  if (/(\d)\1{4,}/.test(digitsOnly)) {
    if (!flags.includes('suspicious_repeated_digits')) {
      riskScore += 12
      flags.push('suspicious_repeated_digits')
      details.push({ rule: 'repeated_sequence', flag: 'suspicious_repeated_digits', points: 12 })
    }
  }
  
  return {
    riskScore: Math.min(riskScore, 100),
    riskLevel: calculateRiskLevel(Math.min(riskScore, 100)),
    flags,
    details
  }
}

// ============================================
// RISK LEVEL CALCULATOR
// ============================================

export function calculateRiskLevel(score: number): 'safe' | 'suspicious' | 'high_risk' {
  if (score <= 30) return 'safe'
  if (score <= 60) return 'suspicious'
  return 'high_risk'
}

// ============================================
// FALLBACK EXPLANATION
// ============================================

const FLAG_DESCRIPTIONS: Record<string, string> = {
  urgency_pressure: 'Contains urgent language designed to pressure quick decisions',
  otp_kyc_request: 'Requests sensitive information like OTP or KYC details',
  account_threat: 'Threatens account suspension or blocking',
  lottery_reward_bait: 'Promises prizes, rewards, or lottery winnings',
  suspicious_job_offer: 'Offers suspicious job with unrealistic earnings',
  authority_impersonation: 'May be impersonating banks or government',
  money_request: 'Requests money transfer or payment',
  poor_grammar: 'Contains suspicious grammar patterns',
  contains_link: 'Contains links that need verification',
  ip_based_url: 'URL uses IP address instead of domain name',
  suspicious_tld: 'Uses suspicious domain extension',
  url_shortener: 'Uses URL shortener to hide actual destination',
  brand_spoofing: 'May be impersonating a known brand',
  excessive_subdomains: 'Has suspicious number of subdomains',
  suspicious_long_url: 'Unusually long URL',
  random_string_url: 'Contains random characters in URL',
  foreign_country_code: 'Phone number from foreign country',
  invalid_number_pattern: 'Invalid phone number pattern',
  suspicious_number_length: 'Suspicious phone number length',
  suspicious_repeated_digits: 'Phone has suspicious repeated digits'
}

export function generateFallbackExplanation(
  riskLevel: 'safe' | 'suspicious' | 'high_risk',
  flags: string[]
): string {
  const parts: string[] = []
  
  if (riskLevel === 'high_risk') {
    parts.push('⚠️ HIGH RISK: This appears to be a potential scam.')
  } else if (riskLevel === 'suspicious') {
    parts.push('⚡ SUSPICIOUS: This has some concerning patterns.')
  } else {
    parts.push('✅ LOW RISK: No major red flags detected.')
  }
  
  if (flags.length > 0) {
    const descriptions = flags
      .slice(0, 3)
      .map(f => FLAG_DESCRIPTIONS[f] || f.replace(/_/g, ' '))
    parts.push('Detected issues: ' + descriptions.join('; ') + '.')
  }
  
  if (riskLevel !== 'safe') {
    parts.push('Do NOT click links, share OTP, or send money. Verify through official channels.')
  }
  
  return parts.join(' ')
}

// ============================================
// MAIN ANALYZE FUNCTION
// ============================================

export function analyze(input: string, type?: 'message' | 'url' | 'phone' | 'auto'): FullAnalysisResult {
  const normalized = normalizeInput(input)
  const inputType = type === 'auto' || !type ? detectInputType(normalized) : type
  const language = detectLanguage(normalized)
  
  let analysis: AnalysisResult
  
  switch (inputType) {
    case 'url':
      analysis = analyzeUrl(normalized)
      break
    case 'phone':
      analysis = analyzePhone(normalized)
      break
    default:
      analysis = analyzeMessage(normalized)
  }
  
  const explanation = generateFallbackExplanation(analysis.riskLevel, analysis.flags)
  
  return {
    ...analysis,
    inputType,
    language,
    explanation,
    disclaimer: 'This is a risk-based analysis, not a verification. Always verify through official channels.'
  }
}
