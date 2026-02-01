import { NextResponse } from 'next/server'
import { analyze, calculateRiskLevel } from '@/lib/scam-analyzer'

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || ''
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent'

// Flag descriptions for better AI context
const FLAG_LABELS: Record<string, string> = {
  urgency_pressure: 'Urgency/pressure tactics detected',
  otp_kyc_request: 'OTP/KYC/password request found',
  account_threat: 'Account blocking threat',
  lottery_reward_bait: 'Lottery/prize/reward scam pattern',
  suspicious_job_offer: 'Fake job offer pattern',
  authority_impersonation: 'Impersonating bank/government',
  money_request: 'Money transfer request',
  poor_grammar: 'Suspicious grammar/formatting',
  contains_link: 'Contains suspicious link',
  delivery_scam: 'Fake delivery notification',
  loan_scam: 'Instant loan scam pattern',
  investment_scam: 'Investment/trading fraud pattern',
  chain_message: 'Forward/viral chain message',
  ip_based_url: 'URL uses IP address (hiding real domain)',
  suspicious_tld: 'Suspicious domain extension',
  url_shortener: 'Shortened URL hiding destination',
  brand_spoofing: 'Fake/lookalike brand domain',
  excessive_subdomains: 'Too many subdomains (suspicious)',
  suspicious_long_url: 'Unusually long URL',
  random_string_url: 'Random characters in URL',
  foreign_country_code: 'Foreign phone number',
  invalid_number_pattern: 'Invalid phone pattern',
  suspicious_number_length: 'Wrong number length',
  suspicious_repeated_digits: 'Repeated digits pattern'
}

async function getGeminiExplanation(
  inputType: string,
  riskScore: number,
  flags: string[],
  language: string,
  originalInput: string
): Promise<string | null> {
  if (!GEMINI_API_KEY) return null
  
  const riskLevel = calculateRiskLevel(riskScore)
  const flagDescriptions = flags.map(f => FLAG_LABELS[f] || f).join(', ')
  
  // Truncate input for safety
  const safeInput = originalInput.length > 300 ? originalInput.slice(0, 300) + '...' : originalInput
  
  const prompt = `Tum ek cybersecurity assistant ho. Ek ${inputType} analyze hua hai rule-based system se.

INPUT: "${safeInput}"

RISK SCORE: ${riskScore}/100 (${riskLevel === 'high_risk' ? 'KHATARNAK' : riskLevel === 'suspicious' ? 'SHAK' : 'SAFE'})
DETECTED ISSUES: ${flagDescriptions || 'None'}

Tumhara kaam hai SIRF 2-3 lines mein explain karna:
1. Ye ${riskLevel === 'high_risk' ? 'SCAM/FAKE kyun lag raha hai' : riskLevel === 'suspicious' ? 'suspicious kyun hai' : 'safe kyun lag raha hai'}
2. User ko kya NAHI karna chahiye
3. Sahi action kya le

RULES:
- Maximum 3 lines, short aur clear
- ${language === 'hindi' || language === 'hinglish' ? 'Hindi/Hinglish mein jawab do' : 'English mein jawab do'}
- Emoji use karo for clarity
- Direct bolo - "Ye FAKE hai" ya "Ye SAFE hai"
- Naya assessment mat karo, sirf detected issues explain karo`

  try {
    const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.4,
          maxOutputTokens: 150,
          topP: 0.8
        },
        safetySettings: [
          { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
        ]
      })
    })
    
    if (response.ok) {
      const result = await response.json()
      const text = result.candidates?.[0]?.content?.parts?.[0]?.text
      if (text) {
        // Clean up response
        return text.trim().replace(/\n{3,}/g, '\n\n')
      }
    }
    return null
  } catch (error) {
    console.error('Gemini API error:', error)
    return null
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    
    if (!body || !body.input) {
      return NextResponse.json({ error: 'No input provided' }, { status: 400 })
    }
    
    const input = body.input?.trim() || ''
    const type = body.type || 'auto'
    
    if (!input) {
      return NextResponse.json({ error: 'Empty input' }, { status: 400 })
    }
    
    // Run rule-based analysis
    const result = analyze(input, type)
    
    // Try to get AI explanation (does NOT affect risk score)
    const aiExplanation = await getGeminiExplanation(
      result.inputType,
      result.riskScore,
      result.flags,
      result.language,
      input
    )
    
    return NextResponse.json({
      success: true,
      input_type: result.inputType,
      language: result.language,
      risk_score: result.riskScore,
      risk_level: result.riskLevel,
      flags: result.flags,
      details: result.details,
      embedded_urls: result.embeddedUrls || [],
      embedded_phones: result.embeddedPhones || [],
      explanation: aiExplanation || result.explanation,
      disclaimer: result.disclaimer
    })
    
  } catch (error) {
    console.error('Analysis error:', error)
    return NextResponse.json(
      { error: 'Analysis failed', success: false },
      { status: 500 }
    )
  }
}
