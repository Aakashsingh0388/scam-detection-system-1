'use client'

import { useState } from 'react'
import { Shield, MessageSquare, Link2, Phone, Search, AlertTriangle, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'

type TabType = 'message' | 'url' | 'phone'
type RiskLevel = 'safe' | 'suspicious' | 'high_risk'

interface AnalysisResult {
  success: boolean
  input_type: string
  language: string
  risk_score: number
  risk_level: RiskLevel
  flags: string[]
  details: Array<{ rule: string; flag: string; points: number }>
  embedded_urls: string[]
  embedded_phones: string[]
  explanation: string
  disclaimer: string
}

const FLAG_LABELS: Record<string, string> = {
 urgency_pressure: 'Urgency/Pressure tactics – Forced to act quickly',
otp_kyc_request: 'OTP/KYC requested – This is a SCAM!',
account_threat: 'Threat of account suspension/closure',
lottery_reward_bait: 'Lottery/Prize lure – This is FAKE!',
suspicious_job_offer: 'Fake job offer pattern',
authority_impersonation: 'Fraud by impersonating Bank/Government',
money_request: 'Attempt to ask for money',
poor_grammar: 'Poor grammar – A sign of a scammer',
contains_link: 'Suspicious link – Do NOT click!',
delivery_scam: 'Fake delivery notification',
loan_scam: 'Instant loan scam pattern',
investment_scam: 'Investment/Trading fraud',
chain_message: 'Forwarded/Viral chain message',
ip_based_url: 'IP-based URL – Domain is hidden',
suspicious_tld: 'Suspicious domain (.xyz, .top etc)',
url_shortener: 'Shortened URL – Original link is hidden',
brand_spoofing: 'Fake brand website',
excessive_subdomains: 'Too many subdomains',
suspicious_long_url: 'Very long URL – Suspicious',
random_string_url: 'Random characters – Fake URL',
foreign_country_code: 'Foreign country code (+234, +1 etc)',
invalid_number_pattern: 'Invalid phone number pattern',
suspicious_number_length: 'Incorrect phone number length',
suspicious_repeated_digits: 'Repeated digits – Fake number'

}

export default function ScamShieldPage() {
  const [activeTab, setActiveTab] = useState<TabType>('message')
  const [messageInput, setMessageInput] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [phoneInput, setPhoneInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [showExamples, setShowExamples] = useState(false)

  const tabs = [
    { id: 'message' as TabType, label: 'Message Scan', icon: MessageSquare },
    { id: 'url' as TabType, label: 'Link Scan', icon: Link2 },
    { id: 'phone' as TabType, label: 'Number Scan', icon: Phone },
  ]

  const getCurrentInput = () => {
    switch (activeTab) {
      case 'message': return messageInput
      case 'url': return urlInput
      case 'phone': return phoneInput
    }
  }

  const handleAnalyze = async () => {
    const input = getCurrentInput().trim()
    if (!input) {
      alert('Please enter something to analyze.')
      return
    }

    setIsLoading(true)
    setResult(null)

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input, type: activeTab }),
      })

      const data = await response.json()
      if (data.success) {
        setResult(data)
      } else {
        alert(data.error || 'Analysis failed')
      }
    } catch {
      alert('Analysis failed. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case 'safe': return 'text-emerald-600'
      case 'suspicious': return 'text-amber-600'
      case 'high_risk': return 'text-red-600'
    }
  }

  const getRiskBgColor = (level: RiskLevel) => {
    switch (level) {
      case 'safe': return 'bg-emerald-50 text-emerald-700 border-emerald-200'
      case 'suspicious': return 'bg-amber-50 text-amber-700 border-amber-200'
      case 'high_risk': return 'bg-red-50 text-red-700 border-red-200'
    }
  }

  const getMeterColor = (level: RiskLevel) => {
    switch (level) {
      case 'safe': return 'bg-gradient-to-r from-emerald-500 to-emerald-400'
      case 'suspicious': return 'bg-gradient-to-r from-amber-500 to-amber-400'
      case 'high_risk': return 'bg-gradient-to-r from-red-500 to-red-400'
    }
  }

  const getRiskIcon = (level: RiskLevel) => {
    switch (level) {
      case 'safe': return <CheckCircle className="w-5 h-5" />
      case 'suspicious': return <AlertCircle className="w-5 h-5" />
      case 'high_risk': return <AlertTriangle className="w-5 h-5" />
    }
  }

  // Quick example datasets
  const messageExamples = {
    scam: [
      "Congratulations! You won ₹50,000. Click bit.ly/win-now and share OTP to claim.",
      "Your account will be suspended. Verify now: http://secure-bank-verify.xyz/login",
      "You've been selected for a prize. Send ₹500 as processing fee to confirm.",
      "Update your KYC immediately: amaz0n-secure.xyz/kyc",
      "Confirm payment of ₹999 to receive refund. Reply with your UPI PIN.",
      "Work from home, earn ₹5,000/day. Pay ₹100 registration now.",
      "Trusted courier couldn't deliver. Click tinyurl.com/deliver-now to reschedule.",
      "Police complaint filed against you. Call 1800-000-000 immediately to avoid arrest.",
      "Your Netflix account has unusual activity. Login at netflix.verify-login.info",
      "Claim free iPhone now: http://free-gift.top/claim — hurry!"
    ],
    safe: [
      "Hi Aakash, the meeting is at 3pm today. Please confirm.",
      "Your OTP is 482910 for transaction at MyBank. Do not share this with anyone.",
      "Reminder: Your subscription renews on Feb 1. Visit your account to manage.",
      "Hey, can you send the report by EOD? Thanks!",
      "Hi, this is your delivery from Flipkart. Tracking ID: FK123456789. Track here: flipkart.com/track",
      "Your appointment with Dr. Sharma is confirmed for 10:30 AM tomorrow.",
      "Bank alert: ₹500 debited from your account. If unauthorised, contact support.",
      "Welcome to our newsletter — expect weekly updates about offers.",
      "Hi, this is John from HR — please complete your onboarding forms.",
      "Your parcel is out for delivery. Courier: Delhivery. Ref: DLV12345"
    ]
  }

  const urlExamples = {
    scam: [
      "http://amaz0n-secure.xyz/login?ref=12345",
      "http://192.168.0.1/verify",
      "https://bit.ly/free-gift-login",
      "http://paypal.verify-account.info/confirm",
      "http://xn--googl-9q9a.com/login",
      "http://secure-bank-login.top/authorize",
      "http://tinyurl.com/claim-prize",
      "http://netflix-support.ga/verify",
      "http://free-reward.click/claim",
      "http://signup.verify-paypal.com.scamdomain.com/login"
    ],
    safe: [
      "https://google.com",
      "https://github.com/your-repo",
      "https://www.flipkart.com/product/12345",
      "https://nextjs.org/docs",
      "https://paypal.com",
      "https://amazon.in",
      "https://bankname.co.in/login (official bank domain example)",
      "https://linkedin.com/in/username",
      "https://wikipedia.org/wiki/Scam",
      "https://example.com/about"
    ]
  }

  const phoneExamples = {
    scam: [
      "+2348123456789",
      "+1-999-999-9999",
      "09999999999",
      "9999999999",
      "+919876543210 (unsolicited caller claiming bank)",
      "+447777777777",
      "+8801712345678",
      "0123456789",
      "+911234567890 (suspicious repeated pattern)",
      "+1 800 000 0000"
    ],
    safe: [
      "+91 98765 43210",
      "+1 415 555 2671",
      "+44 20 7946 0958",
      "+91 22 1234 5678",
      "+91 80 1234 5678",
      "+91 98765 43211",
      "+61 2 9374 4000",
      "+91 70123 45678",
      "+1 212 555 0198",
      "+91 40 1234 5678"
    ]
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      alert('Copied to clipboard')
    } catch {
      alert('Copy failed')
    }
  }

  const useExample = (text: string) => {
    if (activeTab === 'message') setMessageInput(text)
    if (activeTab === 'url') setUrlInput(text)
    if (activeTab === 'phone') setPhoneInput(text)
    setShowExamples(false)
  }

  const formatRiskLevel = (level: RiskLevel) => {
    switch (level) {
      case 'safe': return 'SAFE'
      case 'suspicious': return 'SHAK - Be Careful!'
      case 'high_risk': return 'FAKE / SCAM!'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 via-white to-slate-50">
      <div className="max-w-3xl mx-auto px-4 py-10">
        {/* Header */}
        <header className="text-center mb-8">
          <div className="inline-flex items-center gap-4 bg-gradient-to-r from-white/80 to-white/60 backdrop-blur-sm border border-slate-100 rounded-2xl px-5 py-3 shadow-lg">
            <div className="p-2 rounded-full bg-gradient-to-br from-blue-600 to-indigo-500 text-white shadow-md">
              <Shield className="w-10 h-10" />
            </div>
            <div className="text-left">
              <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">ScamShield AI</h1>
              <p className="text-sm text-slate-500 mt-0.5">Not just detecting scams — explaining them.</p>
            </div>
          </div>
        </header>

        {/* Tab Navigation */}
        <div className="flex gap-2 p-1.5 bg-white/60 rounded-2xl shadow-sm mb-6 backdrop-blur-sm border border-slate-100">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => { setActiveTab(tab.id); setResult(null) }}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-sm font-medium transition-all',
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-lg transform scale-100'
                  : 'text-slate-600 hover:bg-slate-50 hover:scale-[1.01]'
              )}
            >
              <tab.icon className="w-4 h-4" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>

        {/* Input Section */}
        <div className="bg-white/80 rounded-2xl shadow-lg p-6 mb-6 border border-slate-100 backdrop-blur-sm">
          {activeTab === 'message' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Paste suspicious SMS, WhatsApp, or Email content:
              </label>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Example: Congratulations! You've won ₹50,000. Click here to claim: bit.ly/win-prize. Share OTP to verify."
                rows={5}
                className="w-full px-4 py-3 border border-slate-200 rounded-lg bg-white/60 focus:bg-white focus:border-blue-500 focus:outline-none transition-all resize-none text-slate-900 placeholder:text-slate-400 shadow-sm"
              />
            </div>
          )}

          {activeTab === 'url' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Paste suspicious link or URL:
              </label>
              <textarea
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Example: http://amaz0n-secure.xyz/login?ref=12345"
                rows={3}
                className="w-full px-4 py-3 border-2 border-slate-200 rounded-lg bg-slate-50 focus:bg-white focus:border-blue-500 focus:outline-none transition-colors resize-none text-slate-900 placeholder:text-slate-400"
              />
            </div>
          )}

          {activeTab === 'phone' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Enter suspicious phone number:
              </label>
              <textarea
                value={phoneInput}
                onChange={(e) => setPhoneInput(e.target.value)}
                placeholder="Example: +234 812 345 6789 or 9876543210"
                rows={2}
                className="w-full px-4 py-3 border-2 border-slate-200 rounded-lg bg-slate-50 focus:bg-white focus:border-blue-500 focus:outline-none transition-colors resize-none text-slate-900 placeholder:text-slate-400"
              />
            </div>
          )}

          <button
            onClick={handleAnalyze}
            disabled={isLoading}
            className="w-full mt-5 flex items-center justify-center gap-2 py-4 px-6 bg-gradient-to-r from-blue-600 to-indigo-600 disabled:from-slate-400 disabled:to-slate-400 text-white font-semibold rounded-xl transition-transform transform hover:-translate-y-0.5 shadow-lg hover:shadow-xl disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Search className="w-5 h-5" />
                Analyze
              </>
            )}
          </button>

          {/* Quick Examples */}
          <div className="mt-4 flex items-center justify-between gap-3">
            <button
              onClick={() => setShowExamples(!showExamples)}
              className="flex-1 inline-flex items-center justify-center gap-2 py-2 px-3 border border-slate-200 rounded-lg bg-white text-sm hover:bg-slate-50"
            >
              Quick Example
            </button>
            <div className="text-xs text-slate-400">Tap to view sample scam / safe inputs</div>
          </div>

          {showExamples && (
            <div className="mt-4 bg-white/60 border border-slate-100 rounded-2xl p-4 backdrop-blur-sm shadow-inner animate-slide-up">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold mb-2 text-sm">Scam / Fraud Examples</h4>
                  <div className="space-y-2">
                    {(activeTab === 'message' ? messageExamples.scam : activeTab === 'url' ? urlExamples.scam : phoneExamples.scam).map((s, i) => (
                      <div key={i} className="flex items-start justify-between gap-2 p-3 bg-white rounded-lg border hover:shadow-md transition-shadow">
                        <div className="text-xs text-slate-700 break-words flex-1">{s}</div>
                        <div className="flex-shrink-0 ml-3 flex flex-col gap-2">
                          <button onClick={() => useExample(s)} className="px-3 py-1.5 text-xs bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-md shadow">Use</button>
                          <button onClick={() => copyToClipboard(s)} className="px-3 py-1.5 text-xs border rounded-md">Copy</button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold mb-2 text-sm">Safe Examples</h4>
                  <div className="space-y-2">
                    {(activeTab === 'message' ? messageExamples.safe : activeTab === 'url' ? urlExamples.safe : phoneExamples.safe).map((s, i) => (
                      <div key={i} className="flex items-start justify-between gap-2 p-3 bg-white rounded-lg border hover:shadow-md transition-shadow">
                        <div className="text-xs text-slate-700 break-words flex-1">{s}</div>
                        <div className="flex-shrink-0 ml-3 flex flex-col gap-2">
                          <button onClick={() => useExample(s)} className="px-3 py-1.5 text-xs bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-md shadow">Use</button>
                          <button onClick={() => copyToClipboard(s)} className="px-3 py-1.5 text-xs border rounded-md">Copy</button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Results Section */}
        {result && (
          <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-300">
            {/* Risk Score Card */}
            <div className={cn(
              'bg-white rounded-xl shadow-sm p-6 border-l-4',
              result.risk_level === 'safe' && 'border-l-emerald-500',
              result.risk_level === 'suspicious' && 'border-l-amber-500',
              result.risk_level === 'high_risk' && 'border-l-red-500'
            )}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-slate-900">Risk Assessment</h3>
                <span className={cn(
                  'flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold border',
                  getRiskBgColor(result.risk_level)
                )}>
                  {getRiskIcon(result.risk_level)}
                  {formatRiskLevel(result.risk_level)}
                </span>
              </div>

              {/* Risk Meter */}
              <div className="mb-4">
                <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full transition-all duration-500', getMeterColor(result.risk_level))}
                    style={{ width: `${result.risk_score}%` }}
                  />
                </div>
                <div className="flex justify-between mt-2 text-xs text-slate-500">
                  <span>Safe</span>
                  <span>Suspicious</span>
                  <span>High Risk</span>
                </div>
              </div>

              <div className="text-center">
                <span className={cn('text-5xl font-bold', getRiskColor(result.risk_level))}>
                  {result.risk_score}
                </span>
                <span className="text-xl text-slate-400"> / 100</span>
              </div>
            </div>

            {/* Red Flags */}
            {result.flags.length > 0 && (
              <div className="bg-white rounded-xl shadow-sm p-6">
                <h3 className="font-semibold text-slate-900 mb-4 flex items-center gap-2">
                  <span className="text-lg">🚩</span> Red Flags Detected
                </h3>
                <ul className="space-y-2">
                  {result.flags.map((flag, i) => (
                    <li
                      key={i}
                      className="flex items-center gap-3 p-3 bg-red-50 rounded-lg text-red-800 text-sm"
                    >
                      <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                      {FLAG_LABELS[flag] || flag.replace(/_/g, ' ')}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* AI Explanation */}
            <div className="bg-white rounded-xl shadow-sm p-6">
              <h3 className="font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <span className="text-lg">🧠</span> AI Explanation
              </h3>
              <p className="text-slate-700 leading-relaxed p-4 bg-slate-50 rounded-lg border-l-4 border-blue-500">
                {result.explanation}
              </p>
            </div>

            {/* Analysis Details */}
            <div className="bg-white rounded-xl shadow-sm p-6">
              <h3 className="font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <span className="text-lg">📊</span> Analysis Details
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between py-2 border-b border-slate-100">
                  <span className="text-slate-500">Input Type</span>
                  <span className="font-medium text-slate-900 capitalize">{result.input_type}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-100">
                  <span className="text-slate-500">Language Detected</span>
                  <span className="font-medium text-slate-900 capitalize">{result.language}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-slate-100">
                  <span className="text-slate-500">Rules Triggered</span>
                  <span className="font-medium text-slate-900">{result.details.length}</span>
                </div>

                {result.embedded_urls?.length > 0 && (
                  <div className="pt-2">
                    <p className="text-slate-500 mb-2">Embedded URLs Found:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.embedded_urls.map((url, i) => (
                        <code key={i} className="px-2 py-1 bg-slate-100 rounded text-xs break-all text-slate-700">
                          {url}
                        </code>
                      ))}
                    </div>
                  </div>
                )}

                {result.embedded_phones?.length > 0 && (
                  <div className="pt-2">
                    <p className="text-slate-500 mb-2">Phone Numbers Found:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.embedded_phones.map((phone, i) => (
                        <code key={i} className="px-2 py-1 bg-slate-100 rounded text-xs text-slate-700">
                          {phone}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Disclaimer */}
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 text-amber-800 text-sm">
              <p>
                <strong>⚠️ Disclaimer:</strong> {result.disclaimer}
              </p>
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="text-center mt-10 py-6 text-sm text-slate-500">
          <p>Built for Hackathon Demo • Rule-based detection with AI explanation</p>
          <p className="mt-1 text-xs opacity-80">AI explains findings — it does NOT make detection decisions</p>
        </footer>
      </div>
    </div>
  )
}
