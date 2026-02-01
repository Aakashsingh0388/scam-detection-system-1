/**
 * ScamShield AI - Frontend Script
 * Handles UI interactions and API communication
 */

// ============================================
// DOM ELEMENTS
// ============================================

const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const analyzeBtn = document.getElementById('analyze-btn');
const resultsSection = document.getElementById('results-section');

// Input elements
const messageInput = document.getElementById('message-input');
const urlInput = document.getElementById('url-input');
const phoneInput = document.getElementById('phone-input');

// Result elements
const riskBadge = document.getElementById('risk-badge');
const meterFill = document.getElementById('meter-fill');
const riskScoreValue = document.getElementById('risk-score-value');
const flagsCard = document.getElementById('flags-card');
const flagsList = document.getElementById('flags-list');
const explanationText = document.getElementById('explanation-text');
const detailsCard = document.getElementById('details-card');
const detailsContent = document.getElementById('details-content');

// Track current tab
let currentTab = 'message';

// ============================================
// API CONFIGURATION
// ============================================

const API_URL = '/api/analyze';

// ============================================
// TAB NAVIGATION
// ============================================

tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetTab = btn.dataset.tab;
        
        // Update active tab button
        tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update active tab content
        tabContents.forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${targetTab}-tab`).classList.add('active');
        
        // Update current tab tracker
        currentTab = targetTab;
        
        // Hide results when switching tabs
        resultsSection.style.display = 'none';
    });
});

// ============================================
// GET CURRENT INPUT
// ============================================

function getCurrentInput() {
    switch (currentTab) {
        case 'message':
            return { input: messageInput.value.trim(), type: 'message' };
        case 'url':
            return { input: urlInput.value.trim(), type: 'url' };
        case 'phone':
            return { input: phoneInput.value.trim(), type: 'phone' };
        default:
            return { input: '', type: 'auto' };
    }
}

// ============================================
// ANALYZE FUNCTION
// ============================================

async function analyze() {
    const { input, type } = getCurrentInput();
    
    // Validate input
    if (!input) {
        alert('Please enter something to analyze.');
        return;
    }
    
    // Show loading state
    setLoadingState(true);
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ input, type }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data);
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        console.error('Analysis error:', error);
        alert('Analysis failed. Please try again.');
    } finally {
        setLoadingState(false);
    }
}

// ============================================
// DISPLAY RESULTS
// ============================================

function displayResults(data) {
    const { risk_score, risk_level, flags, explanation, details, embedded_urls, embedded_phones, input_type, language } = data;
    
    // Show results section
    resultsSection.style.display = 'block';
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    // Update risk badge
    riskBadge.textContent = formatRiskLevel(risk_level);
    riskBadge.className = `risk-badge ${risk_level.replace('_', '-')}`;
    
    // Update risk meter
    meterFill.style.width = `${risk_score}%`;
    meterFill.className = `meter-fill ${risk_level.replace('_', '-')}`;
    
    // Animate risk score
    animateNumber(riskScoreValue, risk_score);
    
    // Update risk card styling
    const riskCard = document.querySelector('.risk-card');
    riskCard.className = `result-card risk-card ${risk_level.replace('_', '-')}-result`;
    
    // Display flags
    if (flags && flags.length > 0) {
        flagsCard.style.display = 'block';
        flagsList.innerHTML = flags
            .map(flag => `<li>${formatFlag(flag)}</li>`)
            .join('');
    } else {
        flagsCard.style.display = 'none';
    }
    
    // Display explanation
    explanationText.textContent = explanation || 'No explanation available.';
    
    // Display details
    if (details && details.length > 0) {
        detailsCard.style.display = 'block';
        let detailsHTML = '';
        
        // Input type info
        detailsHTML += `
            <div class="detail-item">
                <span class="detail-label">Input Type</span>
                <span class="detail-value">${formatInputType(input_type)}</span>
            </div>
        `;
        
        // Language info
        detailsHTML += `
            <div class="detail-item">
                <span class="detail-label">Language Detected</span>
                <span class="detail-value">${capitalize(language)}</span>
            </div>
        `;
        
        // Rule breakdown
        detailsHTML += `
            <div class="detail-item">
                <span class="detail-label">Rules Triggered</span>
                <span class="detail-value">${details.length}</span>
            </div>
        `;
        
        // Show embedded URLs if any
        if (embedded_urls && embedded_urls.length > 0) {
            detailsHTML += `
                <div class="embedded-section">
                    <h4>Embedded URLs Found:</h4>
                    ${embedded_urls.map(url => `<span class="embedded-item">${escapeHtml(url)}</span>`).join('')}
                </div>
            `;
        }
        
        // Show embedded phones if any
        if (embedded_phones && embedded_phones.length > 0) {
            detailsHTML += `
                <div class="embedded-section">
                    <h4>Phone Numbers Found:</h4>
                    ${embedded_phones.map(phone => `<span class="embedded-item">${escapeHtml(phone)}</span>`).join('')}
                </div>
            `;
        }
        
        detailsContent.innerHTML = detailsHTML;
    } else {
        detailsCard.style.display = 'none';
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function setLoadingState(loading) {
    analyzeBtn.disabled = loading;
    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnLoading = analyzeBtn.querySelector('.btn-loading');
    const btnIcon = analyzeBtn.querySelector('.btn-icon');
    
    if (loading) {
        btnText.style.display = 'none';
        btnIcon.style.display = 'none';
        btnLoading.style.display = 'inline';
        analyzeBtn.classList.add('loading');
    } else {
        btnText.style.display = 'inline';
        btnIcon.style.display = 'inline';
        btnLoading.style.display = 'none';
        analyzeBtn.classList.remove('loading');
    }
}

function formatRiskLevel(level) {
    const levels = {
        'safe': 'Safe',
        'suspicious': 'Suspicious',
        'high_risk': 'High Risk'
    };
    return levels[level] || level;
}

function formatFlag(flag) {
    const flagDescriptions = {
        'urgency_pressure': 'Urgency/Pressure tactics detected',
        'otp_kyc_request': 'OTP/KYC information request',
        'account_threat': 'Account threat/suspension warning',
        'lottery_reward_bait': 'Lottery/Reward bait detected',
        'suspicious_job_offer': 'Suspicious job offer',
        'authority_impersonation': 'Authority impersonation attempt',
        'money_request': 'Money transfer request',
        'poor_grammar': 'Poor grammar/Suspicious language',
        'contains_link': 'Contains suspicious link',
        'ip_based_url': 'IP-based URL (suspicious)',
        'suspicious_tld': 'Suspicious domain extension',
        'url_shortener': 'URL shortener detected',
        'brand_spoofing': 'Brand spoofing attempt',
        'excessive_subdomains': 'Too many subdomains',
        'suspicious_long_url': 'Unusually long URL',
        'random_string_url': 'Random characters in URL',
        'foreign_country_code': 'Foreign country code',
        'invalid_number_pattern': 'Invalid phone pattern',
        'suspicious_number_length': 'Suspicious number length',
        'suspicious_repeated_digits': 'Repeated digit pattern'
    };
    return flagDescriptions[flag] || flag.replace(/_/g, ' ');
}

function formatInputType(type) {
    const types = {
        'message': 'Text Message',
        'url': 'URL/Link',
        'phone': 'Phone Number'
    };
    return types[type] || type;
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function animateNumber(element, target) {
    const duration = 500;
    const start = parseInt(element.textContent) || 0;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * eased);
        
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// ============================================
// EVENT LISTENERS
// ============================================

analyzeBtn.addEventListener('click', analyze);

// Allow Enter key to submit (for single-line inputs)
[urlInput, phoneInput].forEach(input => {
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyze();
        }
    });
});

// Ctrl+Enter for message textarea
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) {
        e.preventDefault();
        analyze();
    }
});

// ============================================
// SAMPLE DATA (for demo purposes)
// ============================================

const sampleData = {
    message: "🎉 Congratulations! You've won ₹50,000 in Lucky Draw! Click here immediately to claim: bit.ly/claim-prize-now. Share your OTP to verify. This offer expires in 24 hours! Act NOW!",
    url: "http://amaz0n-secure-login.xyz/verify?user=12345&ref=claim",
    phone: "+234 812 345 6789"
};

// Pre-fill sample data for demo
messageInput.placeholder = `Example: ${sampleData.message.substring(0, 80)}...`;

// Console welcome message
console.log('%c🛡️ ScamShield AI', 'font-size: 20px; font-weight: bold; color: #2563eb;');
console.log('%cRule-based detection with AI explanation', 'color: #64748b;');
console.log('%c⚠️ AI explains findings - it does NOT make detection decisions', 'color: #f59e0b;');
