/**
 * SafeCheck - Password Strength Analyzer
 * Uses zxcvbn library for entropy and pattern analysis
 * 100% client-side processing for privacy
 */

// Translations
const translations = {
    'pt-BR': {
        home: 'Home',
        title: 'SafeCheck',
        subtitle: 'Analise a força e entropia da sua senha com feedback técnico detalhado',
        privacyBadge: 'Sua senha nunca sai do seu navegador. O processamento é 100% local.',
        passwordLabel: 'Digite sua senha para análise',
        passwordPlaceholder: 'Digite uma senha...',
        showPassword: 'Mostrar senha',
        hidePassword: 'Ocultar senha',
        strengthLabels: ['Muito Fraca', 'Fraca', 'Razoável', 'Forte', 'Muito Forte'],
        entropy: 'Entropia',
        entropyBits: 'bits',
        entropyDescription: 'Quanto maior a entropia, mais difícil de adivinhar. Senhas acima de 60 bits são consideradas seguras para a maioria dos casos.',
        crackTime: 'Tempo de Quebra',
        crackScenarios: {
            online_throttled: 'Ataque online (limitado)',
            online_unthrottled: 'Ataque online (sem limite)',
            offline_slow: 'Ataque offline (lento)',
            offline_fast: 'Ataque offline (GPU cluster)'
        },
        feedback: 'Feedback',
        noFeedback: 'Nenhuma sugestão - senha parece boa!',
        warning: 'Aviso',
        suggestion: 'Sugestão',
        typePassword: 'Digite uma senha para analisar',
        guideTitle: 'Guia de Segurança de Senhas',
        whatIsEntropy: 'O que é Entropia?',
        entropyExplanation: 'Entropia é uma medida matemática da aleatoriedade de uma senha, expressa em bits. Cada bit adicional dobra o número de tentativas necessárias para um atacante adivinhar a senha por força bruta.',
        entropyLevels: 'Níveis de Entropia',
        entropyLevelsList: [
            '< 28 bits: Muito fraca - pode ser quebrada instantaneamente',
            '28-35 bits: Fraca - vulnerável a ataques básicos',
            '36-59 bits: Razoável - resistente a ataques online',
            '60-127 bits: Forte - segura para maioria dos usos',
            '128+ bits: Muito forte - praticamente impossível de quebrar'
        ],
        tipsTitle: 'Dicas para Senhas Fortes',
        tipsList: [
            'Use frases em vez de palavras únicas (ex: "café-gelado-segunda-feira")',
            'Evite informações pessoais como datas de nascimento ou nomes',
            'Não reutilize senhas entre diferentes serviços',
            'Considere usar um gerenciador de senhas',
            'Ative autenticação de dois fatores quando disponível'
        ]
    },
    'en-US': {
        home: 'Home',
        title: 'SafeCheck',
        subtitle: 'Analyze your password strength and entropy with detailed technical feedback',
        privacyBadge: 'Your password never leaves your browser. Processing is 100% local.',
        passwordLabel: 'Enter your password for analysis',
        passwordPlaceholder: 'Type a password...',
        showPassword: 'Show password',
        hidePassword: 'Hide password',
        strengthLabels: ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'],
        entropy: 'Entropy',
        entropyBits: 'bits',
        entropyDescription: 'The higher the entropy, the harder to guess. Passwords above 60 bits are considered secure for most cases.',
        crackTime: 'Crack Time',
        crackScenarios: {
            online_throttled: 'Online attack (throttled)',
            online_unthrottled: 'Online attack (unthrottled)',
            offline_slow: 'Offline attack (slow)',
            offline_fast: 'Offline attack (GPU cluster)'
        },
        feedback: 'Feedback',
        noFeedback: 'No suggestions - password looks good!',
        warning: 'Warning',
        suggestion: 'Suggestion',
        typePassword: 'Type a password to analyze',
        guideTitle: 'Password Security Guide',
        whatIsEntropy: 'What is Entropy?',
        entropyExplanation: 'Entropy is a mathematical measure of password randomness, expressed in bits. Each additional bit doubles the number of attempts needed for an attacker to brute-force guess the password.',
        entropyLevels: 'Entropy Levels',
        entropyLevelsList: [
            '< 28 bits: Very weak - can be cracked instantly',
            '28-35 bits: Weak - vulnerable to basic attacks',
            '36-59 bits: Fair - resistant to online attacks',
            '60-127 bits: Strong - secure for most uses',
            '128+ bits: Very strong - practically impossible to crack'
        ],
        tipsTitle: 'Tips for Strong Passwords',
        tipsList: [
            'Use phrases instead of single words (e.g., "cold-coffee-monday-morning")',
            'Avoid personal information like birthdays or names',
            'Never reuse passwords across different services',
            'Consider using a password manager',
            'Enable two-factor authentication when available'
        ]
    }
};

// Get current language from HTML attribute
function getCurrentLang() {
    return document.documentElement.getAttribute('data-lang') || 'pt-BR';
}

function t(key) {
    const lang = getCurrentLang();
    const keys = key.split('.');
    let value = translations[lang];
    for (const k of keys) {
        value = value?.[k];
    }
    return value || key;
}

// DOM Elements
let passwordInput, toggleBtn, gaugeNeedle, strengthLabel, strengthScore;
let entropyValue, entropyDesc, crackTimeList, feedbackList;
let resultsContainer;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeElements();
    setupEventListeners();
    updateDisplay(null); // Show empty state
});

function initializeElements() {
    passwordInput = document.getElementById('passwordInput');
    toggleBtn = document.getElementById('toggleVisibility');
    gaugeNeedle = document.getElementById('gaugeNeedle');
    strengthLabel = document.getElementById('strengthLabel');
    strengthScore = document.getElementById('strengthScore');
    entropyValue = document.getElementById('entropyValue');
    entropyDesc = document.getElementById('entropyDesc');
    crackTimeList = document.getElementById('crackTimeList');
    feedbackList = document.getElementById('feedbackList');
    resultsContainer = document.getElementById('resultsContainer');
}

function setupEventListeners() {
    // Password input - real-time analysis
    if (passwordInput) {
        passwordInput.addEventListener('input', debounce(analyzePassword, 100));
    }
    
    // Toggle password visibility
    if (toggleBtn) {
        toggleBtn.addEventListener('click', togglePasswordVisibility);
    }
}

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Toggle password visibility
function togglePasswordVisibility() {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    
    // Update icon
    const eyeOpen = toggleBtn.querySelector('.eye-open');
    const eyeClosed = toggleBtn.querySelector('.eye-closed');
    
    if (eyeOpen && eyeClosed) {
        eyeOpen.style.display = isPassword ? 'none' : 'block';
        eyeClosed.style.display = isPassword ? 'block' : 'none';
    }
    
    // Update aria-label
    toggleBtn.setAttribute('aria-label', isPassword ? t('hidePassword') : t('showPassword'));
}

// Main analysis function
function analyzePassword() {
    const password = passwordInput.value;
    
    if (!password) {
        updateDisplay(null);
        return;
    }
    
    // Check if zxcvbn is loaded
    if (typeof zxcvbn === 'undefined') {
        console.error('zxcvbn library not loaded');
        return;
    }
    
    const result = zxcvbn(password);
    updateDisplay(result);
}

// Update all display elements
function updateDisplay(result) {
    if (!result) {
        // Empty state
        updateGauge(0);
        if (strengthLabel) {
            strengthLabel.textContent = '-';
            strengthLabel.className = 'strength-label';
        }
        if (strengthScore) strengthScore.textContent = '';
        if (resultsContainer) resultsContainer.style.display = 'none';
        return;
    }
    
    // Show results
    if (resultsContainer) resultsContainer.style.display = 'grid';
    
    // Update gauge (score is 0-4)
    updateGauge(result.score);
    
    // Update strength label
    updateStrengthLabel(result.score);
    
    // Update entropy
    updateEntropy(result);
    
    // Update crack times
    updateCrackTimes(result);
    
    // Update feedback
    updateFeedback(result);
}

// Update the semicircle gauge
function updateGauge(score) {
    if (!gaugeNeedle) return;
    
    // Map score (0-4) to angle (-90deg to 90deg)
    const angle = -90 + (score / 4) * 180;
    gaugeNeedle.style.transform = `translateX(-50%) rotate(${angle}deg)`;
    
    // Update needle color based on score
    const colors = [
        'var(--strength-weak)',
        'var(--strength-fair)',
        'var(--strength-good)',
        'var(--strength-strong)',
        'var(--strength-excellent)'
    ];
    gaugeNeedle.style.background = colors[score] || colors[0];
    gaugeNeedle.style.boxShadow = `0 0 15px ${colors[score] || colors[0]}`;
}

// Update strength label and class
function updateStrengthLabel(score) {
    if (!strengthLabel) return;
    
    const labels = t('strengthLabels');
    const classes = ['weak', 'weak', 'fair', 'strong', 'excellent'];
    
    strengthLabel.textContent = labels[score] || labels[0];
    strengthLabel.className = 'strength-label ' + (classes[score] || classes[0]);
    
    if (strengthScore) {
        strengthScore.textContent = `Score: ${score}/4`;
    }
}

// Update entropy display
function updateEntropy(result) {
    if (!entropyValue) return;
    
    // zxcvbn provides guesses_log10, convert to bits (log2)
    const entropyBits = Math.round(result.guesses_log10 * 3.321928); // log2(10) ≈ 3.321928
    
    entropyValue.innerHTML = `${entropyBits} <span>${t('entropyBits')}</span>`;
    
    if (entropyDesc) {
        entropyDesc.textContent = t('entropyDescription');
    }
}

// Update crack time estimates
function updateCrackTimes(result) {
    if (!crackTimeList) return;
    
    const scenarios = t('crackScenarios');
    const times = result.crack_times_display;
    
    crackTimeList.innerHTML = `
        <div class="crack-time-item">
            <span class="crack-scenario">${scenarios.online_throttled}</span>
            <span class="crack-time">${formatTime(times.online_throttling_100_per_hour)}</span>
        </div>
        <div class="crack-time-item">
            <span class="crack-scenario">${scenarios.online_unthrottled}</span>
            <span class="crack-time">${formatTime(times.online_no_throttling_10_per_second)}</span>
        </div>
        <div class="crack-time-item">
            <span class="crack-scenario">${scenarios.offline_slow}</span>
            <span class="crack-time">${formatTime(times.offline_slow_hashing_1e4_per_second)}</span>
        </div>
        <div class="crack-time-item">
            <span class="crack-scenario">${scenarios.offline_fast}</span>
            <span class="crack-time">${formatTime(times.offline_fast_hashing_1e10_per_second)}</span>
        </div>
    `;
}

// Format time display (translate common terms)
function formatTime(time) {
    if (!time) return '-';
    
    const lang = getCurrentLang();
    
    if (lang === 'pt-BR') {
        return time
            .replace('less than a second', 'menos de 1 segundo')
            .replace('instant', 'instantâneo')
            .replace('seconds', 'segundos')
            .replace('second', 'segundo')
            .replace('minutes', 'minutos')
            .replace('minute', 'minuto')
            .replace('hours', 'horas')
            .replace('hour', 'hora')
            .replace('days', 'dias')
            .replace('day', 'dia')
            .replace('months', 'meses')
            .replace('month', 'mês')
            .replace('years', 'anos')
            .replace('year', 'ano')
            .replace('centuries', 'séculos')
            .replace('century', 'século');
    }
    
    return time;
}

// Update feedback section
function updateFeedback(result) {
    if (!feedbackList) return;
    
    const feedback = result.feedback;
    const items = [];
    
    // Add warning if present
    if (feedback.warning) {
        items.push({
            type: 'warning',
            text: translateFeedback(feedback.warning)
        });
    }
    
    // Add suggestions
    if (feedback.suggestions && feedback.suggestions.length > 0) {
        feedback.suggestions.forEach(suggestion => {
            items.push({
                type: 'suggestion',
                text: translateFeedback(suggestion)
            });
        });
    }
    
    if (items.length === 0) {
        feedbackList.innerHTML = `<p class="no-feedback">${t('noFeedback')}</p>`;
        return;
    }
    
    feedbackList.innerHTML = items.map(item => `
        <div class="feedback-item ${item.type}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${item.type === 'warning' 
                    ? '<path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>'
                    : '<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>'}
            </svg>
            <span>${item.text}</span>
        </div>
    `).join('');
}

// Translate zxcvbn feedback messages
function translateFeedback(text) {
    if (getCurrentLang() !== 'pt-BR') return text;
    
    const feedbackTranslations = {
        // Warnings
        'This is a top-10 common password': 'Esta é uma das 10 senhas mais comuns',
        'This is a top-100 common password': 'Esta é uma das 100 senhas mais comuns',
        'This is a very common password': 'Esta é uma senha muito comum',
        'This is similar to a commonly used password': 'Esta é similar a uma senha comum',
        'A word by itself is easy to guess': 'Uma palavra sozinha é fácil de adivinhar',
        'Names and surnames by themselves are easy to guess': 'Nomes e sobrenomes sozinhos são fáceis de adivinhar',
        'Common names and surnames are easy to guess': 'Nomes comuns são fáceis de adivinhar',
        'Straight rows of keys are easy to guess': 'Sequências de teclas em linha são fáceis de adivinhar',
        'Short keyboard patterns are easy to guess': 'Padrões curtos de teclado são fáceis de adivinhar',
        'Repeats like "aaa" are easy to guess': 'Repetições como "aaa" são fáceis de adivinhar',
        'Repeats like "abcabcabc" are only slightly harder to guess than "abc"': 'Repetições como "abcabcabc" são pouco mais difíceis que "abc"',
        'Sequences like abc or 6543 are easy to guess': 'Sequências como abc ou 6543 são fáceis de adivinhar',
        'Recent years are easy to guess': 'Anos recentes são fáceis de adivinhar',
        'Dates are often easy to guess': 'Datas são frequentemente fáceis de adivinhar',
        'This is a commonly used password': 'Esta é uma senha comumente usada',
        
        // Suggestions
        'Add another word or two. Uncommon words are better.': 'Adicione mais uma ou duas palavras. Palavras incomuns são melhores.',
        'Use a longer keyboard pattern with more turns': 'Use um padrão de teclado mais longo com mais mudanças de direção',
        'Avoid repeated words and characters': 'Evite palavras e caracteres repetidos',
        'Avoid sequences': 'Evite sequências',
        'Avoid recent years': 'Evite anos recentes',
        'Avoid years that are associated with you': 'Evite anos associados a você',
        'Avoid dates and years that are associated with you': 'Evite datas e anos associados a você',
        'Capitalization doesn\'t help very much': 'Letras maiúsculas não ajudam muito',
        'All-uppercase is almost as easy to guess as all-lowercase': 'Tudo maiúsculo é quase tão fácil quanto tudo minúsculo',
        'Reversed words aren\'t much harder to guess': 'Palavras invertidas não são muito mais difíceis',
        'Predictable substitutions like \'@\' instead of \'a\' don\'t help very much': 'Substituições previsíveis como "@" por "a" não ajudam muito',
        'Use a few words, avoid common phrases': 'Use algumas palavras, evite frases comuns',
        'No need for symbols, digits, or uppercase letters': 'Não precisa de símbolos, números ou maiúsculas'
    };
    
    return feedbackTranslations[text] || text;
}
