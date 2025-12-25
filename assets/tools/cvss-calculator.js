/**
 * CVSS Calculator v3.1
 * Using official FIRST.org formulas
 */

// ============================================
// State Management
// ============================================
const state = {
    version: '3.1',
    currentStep: 1,
    totalSteps: 4,
    lang: 'pt-BR',
    metrics: {
        AV: null, AC: null, PR: null, UI: null,
        S: null, C: null, I: null, A: null
    }
};

// ============================================
// CVSS v3.1 Calculation Constants
// ============================================
const CVSS31 = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: {
        U: { N: 0.85, L: 0.62, H: 0.27 },
        C: { N: 0.85, L: 0.68, H: 0.50 }
    },
    UI: { N: 0.85, R: 0.62 },
    C: { N: 0, L: 0.22, H: 0.56 },
    I: { N: 0, L: 0.22, H: 0.56 },
    A: { N: 0, L: 0.22, H: 0.56 }
};

// ============================================
// Internationalization
// ============================================
const i18n = {
    'pt-BR': {
        home: 'Home',
        title: 'Calculadora CVSS',
        subtitle: 'Calcule scores de vulnerabilidades usando CVSS v3.1 com interface interativa',
        step_attack: 'Vetor de Ataque',
        step_complexity: 'Complexidade',
        step_privileges: 'Privilégios',
        step_impact: 'Impacto',
        step1_title: 'Vetor de Ataque',
        step1_desc: 'Como o atacante pode explorar esta vulnerabilidade?',
        step2_title: 'Requisitos de Acesso',
        step2_desc: 'Quais privilégios e interações são necessários?',
        step3_title: 'Escopo do Impacto',
        step3_desc: 'A vulnerabilidade afeta outros componentes além do vulnerável?',
        step4_title: 'Impacto (CIA Triad)',
        step4_desc: 'Qual o impacto em Confidencialidade, Integridade e Disponibilidade?',
        prev: 'Anterior',
        next: 'Próximo',
        finish: 'Finalizar',
        vector_label: 'Vector String',
        breakdown: 'Detalhamento',
        base_score: 'Score Base',
        impact: 'Impacto',
        exploitability: 'Explorabilidade',
        copy_vector: 'Copiar Vector',
        generate_report: 'Gerar Relatório',
        reset: 'Resetar',
        copied: 'Copiado para a área de transferência!',
        report_title: 'Relatório de Vulnerabilidade',
        copy_report: 'Copiar Relatório',
        severity_none: 'NENHUM',
        severity_low: 'BAIXO',
        severity_medium: 'MÉDIO',
        severity_high: 'ALTO',
        severity_critical: 'CRÍTICO',
        guide_title: 'Guia Definitivo: Como Classificar Vulnerabilidades',
        guide_intro_title: '1. O que é CVSS?',
        guide_metrics_title: '2. Entendendo as Métricas',
        guide_examples_title: '3. Exemplos Práticos',
        guide_best_title: '4. Boas Práticas',
        guide_errors_title: '5. Erros Comuns'
    },
    'en-US': {
        home: 'Home',
        title: 'CVSS Calculator',
        subtitle: 'Calculate vulnerability scores using CVSS v3.1 with interactive interface',
        step_attack: 'Attack Vector',
        step_complexity: 'Complexity',
        step_privileges: 'Privileges',
        step_impact: 'Impact',
        step1_title: 'Attack Vector',
        step1_desc: 'How can an attacker exploit this vulnerability?',
        step2_title: 'Access Requirements',
        step2_desc: 'What privileges and interactions are required?',
        step3_title: 'Impact Scope',
        step3_desc: 'Does the vulnerability affect components beyond the vulnerable one?',
        step4_title: 'Impact (CIA Triad)',
        step4_desc: 'What is the impact on Confidentiality, Integrity, and Availability?',
        prev: 'Previous',
        next: 'Next',
        finish: 'Finish',
        vector_label: 'Vector String',
        breakdown: 'Breakdown',
        base_score: 'Base Score',
        impact: 'Impact',
        exploitability: 'Exploitability',
        copy_vector: 'Copy Vector',
        generate_report: 'Generate Report',
        reset: 'Reset',
        copied: 'Copied to clipboard!',
        report_title: 'Vulnerability Report',
        copy_report: 'Copy Report',
        severity_none: 'NONE',
        severity_low: 'LOW',
        severity_medium: 'MEDIUM',
        severity_high: 'HIGH',
        severity_critical: 'CRITICAL',
        guide_title: 'Definitive Guide: How to Classify Vulnerabilities',
        guide_intro_title: '1. What is CVSS?',
        guide_metrics_title: '2. Understanding the Metrics',
        guide_examples_title: '3. Practical Examples',
        guide_best_title: '4. Best Practices',
        guide_errors_title: '5. Common Mistakes'
    }
};

// ============================================
// Official FIRST.org RoundUp Function
// Handles floating-point precision issues
// ============================================
function roundUp(input) {
    const int_input = Math.round(input * 100000);
    if ((int_input % 10000) === 0) {
        return int_input / 100000;
    } else {
        return (Math.floor(int_input / 10000) + 1) / 10;
    }
}

// ============================================
// CVSS v3.1 Score Calculation
// ============================================
function calculateCVSS31() {
    const m = state.metrics;

    // Check if all metrics are selected
    if (Object.values(m).some(v => v === null)) {
        return { base: 0, impact: 0, exploitability: 0 };
    }

    const scope = m.S;

    // Exploitability Sub-score
    const exploitability = 8.22 * CVSS31.AV[m.AV] * CVSS31.AC[m.AC] * CVSS31.PR[scope][m.PR] * CVSS31.UI[m.UI];

    // Impact Sub-score (ISS)
    const iss = 1 - ((1 - CVSS31.C[m.C]) * (1 - CVSS31.I[m.I]) * (1 - CVSS31.A[m.A]));

    let impact;
    if (scope === 'U') {
        impact = 6.42 * iss;
    } else {
        impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    // Base Score
    let base;
    if (impact <= 0) {
        base = 0;
    } else if (scope === 'U') {
        base = Math.min(impact + exploitability, 10);
    } else {
        base = Math.min(1.08 * (impact + exploitability), 10);
    }

    // Round up using official FIRST.org method
    base = roundUp(base);
    impact = roundUp(Math.max(0, impact));
    const exploit = roundUp(exploitability);

    return { base: Math.max(0, Math.min(10, base)), impact: impact, exploitability: exploit };
}

// ============================================
// Severity Rating
// ============================================
function getSeverity(score) {
    if (score === 0) return { class: 'none', key: 'severity_none' };
    if (score <= 3.9) return { class: 'low', key: 'severity_low' };
    if (score <= 6.9) return { class: 'medium', key: 'severity_medium' };
    if (score <= 8.9) return { class: 'high', key: 'severity_high' };
    return { class: 'critical', key: 'severity_critical' };
}

// ============================================
// Vector String Generation
// ============================================
function generateVectorString() {
    const m = state.metrics;
    const version = 'CVSS:3.1';

    const parts = [
        `AV:${m.AV || '_'}`,
        `AC:${m.AC || '_'}`,
        `PR:${m.PR || '_'}`,
        `UI:${m.UI || '_'}`,
        `S:${m.S || '_'}`,
        `C:${m.C || '_'}`,
        `I:${m.I || '_'}`,
        `A:${m.A || '_'}`
    ];

    return `${version}/${parts.join('/')}`;
}

// ============================================
// UI Update Functions
// ============================================
function updateScore() {
    const scores = calculateCVSS31();
    const severity = getSeverity(scores.base);

    document.getElementById('scoreValue').textContent = scores.base.toFixed(1);
    document.getElementById('scoreValue').className = `score-value severity-${severity.class}`;

    document.getElementById('severityBadge').textContent = i18n[state.lang][severity.key];
    document.getElementById('severityBadge').className = `severity-badge severity-${severity.class}`;

    document.getElementById('baseScore').textContent = scores.base.toFixed(1);
    document.getElementById('impactScore').textContent = scores.impact.toFixed(1);
    document.getElementById('exploitScore').textContent = scores.exploitability.toFixed(1);

    document.getElementById('vectorString').textContent = generateVectorString();
}

function updateProgress() {
    document.querySelectorAll('.progress-step').forEach((step, index) => {
        const stepNum = index + 1;
        step.classList.remove('active', 'completed');

        if (stepNum < state.currentStep) {
            step.classList.add('completed');
        } else if (stepNum === state.currentStep) {
            step.classList.add('active');
        }
    });
}

function showStep(stepNum) {
    document.querySelectorAll('.step-content').forEach(content => {
        content.classList.remove('active');
    });
    document.querySelector(`.step-content[data-step="${stepNum}"]`).classList.add('active');

    document.getElementById('prevBtn').disabled = stepNum === 1;

    const nextBtn = document.getElementById('nextBtn');
    if (stepNum === state.totalSteps) {
        nextBtn.querySelector('span').textContent = i18n[state.lang].finish;
    } else {
        nextBtn.querySelector('span').textContent = i18n[state.lang].next;
    }
}

function updateLanguage() {
    const lang = i18n[state.lang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (lang[key]) {
            el.textContent = lang[key];
        }
    });
}

// ============================================
// Report Generation
// ============================================
function generateReport(asHtml = false) {
    const m = state.metrics;
    const scores = calculateCVSS31();
    const severity = getSeverity(scores.base);
    const vector = generateVectorString();

    const avText = { N: 'rede (remoto)', A: 'rede adjacente', L: 'local', P: 'físico' };
    const acText = { L: 'baixa', H: 'alta' };
    const prText = { N: 'nenhum privilégio', L: 'privilégios baixos', H: 'privilégios altos' };
    const uiText = { N: 'sem interação do usuário', R: 'interação do usuário' };
    const impactText = { N: 'nenhum', L: 'baixo', H: 'alto' };

    let report = '';
    const bold = asHtml ? ['<strong>', '</strong>'] : ['', ''];
    const br = asHtml ? '<br><br>' : '\n\n';
    const code = asHtml ? ['<code>', '</code>'] : ['', ''];

    if (state.lang === 'pt-BR') {
        report = `${bold[0]}Classificação CVSS ${state.version}${bold[1]}${br}`;
        report += `${bold[0]}Vector String:${bold[1]} ${code[0]}${vector}${code[1]}${br}`;
        report += `${bold[0]}Score Base:${bold[1]} ${scores.base.toFixed(1)} (${i18n[state.lang][severity.key]})${br}`;
        report += `${bold[0]}Análise:${bold[1]}${asHtml ? '<br>' : '\n'}`;
        report += `Esta vulnerabilidade pode ser explorada via ${bold[0]}${avText[m.AV] || 'N/A'}${bold[1]} `;
        report += `com complexidade de ataque ${bold[0]}${acText[m.AC] || 'N/A'}${bold[1]}. `;
        report += `O atacante necessita de ${bold[0]}${prText[m.PR] || 'N/A'}${bold[1]} `;
        report += `e ${bold[0]}${uiText[m.UI] || 'N/A'}${bold[1]} é requerida. `;
        report += `O impacto na confidencialidade é ${bold[0]}${impactText[m.C] || 'N/A'}${bold[1]}, `;
        report += `na integridade é ${bold[0]}${impactText[m.I] || 'N/A'}${bold[1]} `;
        report += `e na disponibilidade é ${bold[0]}${impactText[m.A] || 'N/A'}${bold[1]}.`;
    } else {
        const avTextEn = { N: 'network (remote)', A: 'adjacent network', L: 'local', P: 'physical' };
        const acTextEn = { L: 'low', H: 'high' };
        const prTextEn = { N: 'no privileges', L: 'low privileges', H: 'high privileges' };
        const uiTextEn = { N: 'no user interaction', R: 'user interaction' };
        const impactTextEn = { N: 'none', L: 'low', H: 'high' };

        report = `${bold[0]}CVSS ${state.version} Classification${bold[1]}${br}`;
        report += `${bold[0]}Vector String:${bold[1]} ${code[0]}${vector}${code[1]}${br}`;
        report += `${bold[0]}Base Score:${bold[1]} ${scores.base.toFixed(1)} (${i18n[state.lang][severity.key]})${br}`;
        report += `${bold[0]}Analysis:${bold[1]}${asHtml ? '<br>' : '\n'}`;
        report += `This vulnerability can be exploited via ${bold[0]}${avTextEn[m.AV] || 'N/A'}${bold[1]} `;
        report += `with ${bold[0]}${acTextEn[m.AC] || 'N/A'}${bold[1]} attack complexity. `;
        report += `The attacker requires ${bold[0]}${prTextEn[m.PR] || 'N/A'}${bold[1]} `;
        report += `and ${bold[0]}${uiTextEn[m.UI] || 'N/A'}${bold[1]} is required. `;
        report += `The confidentiality impact is ${bold[0]}${impactTextEn[m.C] || 'N/A'}${bold[1]}, `;
        report += `integrity impact is ${bold[0]}${impactTextEn[m.I] || 'N/A'}${bold[1]}, `;
        report += `and availability impact is ${bold[0]}${impactTextEn[m.A] || 'N/A'}${bold[1]}.`;
    }

    return report;
}

// ============================================
// Safe Report Display (XSS Prevention)
// ============================================
function displayReportSafely(container, reportData) {
    container.textContent = ''; // Clear content safely

    const m = state.metrics;
    const scores = calculateCVSS31();
    const severity = getSeverity(scores.base);
    const vector = generateVectorString();

    const avText = state.lang === 'pt-BR'
        ? { N: 'rede (remoto)', A: 'rede adjacente', L: 'local', P: 'físico' }
        : { N: 'network (remote)', A: 'adjacent network', L: 'local', P: 'physical' };
    const acText = state.lang === 'pt-BR' ? { L: 'baixa', H: 'alta' } : { L: 'low', H: 'high' };
    const prText = state.lang === 'pt-BR'
        ? { N: 'nenhum privilégio', L: 'privilégios baixos', H: 'privilégios altos' }
        : { N: 'no privileges', L: 'low privileges', H: 'high privileges' };
    const uiText = state.lang === 'pt-BR'
        ? { N: 'sem interação do usuário', R: 'interação do usuário' }
        : { N: 'no user interaction', R: 'user interaction' };
    const impactText = state.lang === 'pt-BR'
        ? { N: 'nenhum', L: 'baixo', H: 'alto' }
        : { N: 'none', L: 'low', H: 'high' };

    // Create elements safely
    const title = document.createElement('strong');
    title.textContent = state.lang === 'pt-BR'
        ? `Classificação CVSS ${state.version}`
        : `CVSS ${state.version} Classification`;
    container.appendChild(title);
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    const vectorLabel = document.createElement('strong');
    vectorLabel.textContent = 'Vector String: ';
    container.appendChild(vectorLabel);
    const vectorCode = document.createElement('code');
    vectorCode.textContent = vector;
    container.appendChild(vectorCode);
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    const scoreLabel = document.createElement('strong');
    scoreLabel.textContent = state.lang === 'pt-BR' ? 'Score Base: ' : 'Base Score: ';
    container.appendChild(scoreLabel);
    container.appendChild(document.createTextNode(`${scores.base.toFixed(1)} (${i18n[state.lang][severity.key]})`));
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    const analysisLabel = document.createElement('strong');
    analysisLabel.textContent = state.lang === 'pt-BR' ? 'Análise: ' : 'Analysis: ';
    container.appendChild(analysisLabel);
    container.appendChild(document.createElement('br'));

    const analysis = state.lang === 'pt-BR'
        ? `Esta vulnerabilidade pode ser explorada via ${avText[m.AV] || 'N/A'} com complexidade de ataque ${acText[m.AC] || 'N/A'}. O atacante necessita de ${prText[m.PR] || 'N/A'} e ${uiText[m.UI] || 'N/A'} é requerida. O impacto na confidencialidade é ${impactText[m.C] || 'N/A'}, na integridade é ${impactText[m.I] || 'N/A'} e na disponibilidade é ${impactText[m.A] || 'N/A'}.`
        : `This vulnerability can be exploited via ${avText[m.AV] || 'N/A'} with ${acText[m.AC] || 'N/A'} attack complexity. The attacker requires ${prText[m.PR] || 'N/A'} and ${uiText[m.UI] || 'N/A'} is required. The confidentiality impact is ${impactText[m.C] || 'N/A'}, integrity impact is ${impactText[m.I] || 'N/A'}, and availability impact is ${impactText[m.A] || 'N/A'}.`;

    container.appendChild(document.createTextNode(analysis));
}

// ============================================
// Event Listeners
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Detect language from HTML attribute
    const htmlLang = document.documentElement.getAttribute('data-lang');
    if (htmlLang) {
        state.lang = htmlLang;
    }

    // Version Toggle
    document.querySelectorAll('.version-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const newVersion = btn.getAttribute('data-version');
            if (state.version !== newVersion) {
                document.querySelectorAll('.version-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.version = newVersion;

                // Reset calculator when switching versions
                Object.keys(state.metrics).forEach(key => state.metrics[key] = null);
                document.querySelectorAll('.metric-btn').forEach(b => b.classList.remove('selected'));
                state.currentStep = 1;
                showStep(1);
                updateProgress();
                updateScore();
            }
        });
    });

    // Metric Buttons
    document.querySelectorAll('.metric-buttons').forEach(group => {
        const metric = group.getAttribute('data-metric');
        group.querySelectorAll('.metric-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                group.querySelectorAll('.metric-btn').forEach(b => b.classList.remove('selected'));
                btn.classList.add('selected');
                state.metrics[metric] = btn.getAttribute('data-value');
                updateScore();
            });
        });
    });

    // Navigation
    document.getElementById('prevBtn').addEventListener('click', () => {
        if (state.currentStep > 1) {
            state.currentStep--;
            showStep(state.currentStep);
            updateProgress();
        }
    });

    document.getElementById('nextBtn').addEventListener('click', () => {
        if (state.currentStep < state.totalSteps) {
            state.currentStep++;
            showStep(state.currentStep);
            updateProgress();
        } else {
            // Finalizar - scroll to score panel and highlight it
            const scorePanel = document.querySelector('.score-panel');
            if (scorePanel) {
                scorePanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
                scorePanel.classList.add('highlight');
                setTimeout(() => scorePanel.classList.remove('highlight'), 2000);
            }
        }
    });

    // Copy Vector
    document.getElementById('copyVector').addEventListener('click', () => {
        navigator.clipboard.writeText(generateVectorString());
        const feedback = document.getElementById('copyFeedback');
        feedback.classList.add('show');
        setTimeout(() => feedback.classList.remove('show'), 2000);
    });

    // Generate Report (XSS-safe)
    document.getElementById('generateReport').addEventListener('click', () => {
        const reportContainer = document.getElementById('reportText');
        displayReportSafely(reportContainer);
        document.getElementById('reportModal').classList.add('show');
    });

    // Close Modal
    document.getElementById('closeModal').addEventListener('click', () => {
        document.getElementById('reportModal').classList.remove('show');
    });

    document.getElementById('reportModal').addEventListener('click', (e) => {
        if (e.target.id === 'reportModal') {
            document.getElementById('reportModal').classList.remove('show');
        }
    });

    // Copy Report
    document.getElementById('copyReport').addEventListener('click', () => {
        navigator.clipboard.writeText(generateReport());
        const feedback = document.getElementById('copyFeedback');
        feedback.classList.add('show');
        setTimeout(() => feedback.classList.remove('show'), 2000);
    });

    // Reset
    document.getElementById('resetCalc').addEventListener('click', () => {
        Object.keys(state.metrics).forEach(key => state.metrics[key] = null);
        document.querySelectorAll('.metric-btn').forEach(btn => btn.classList.remove('selected'));
        state.currentStep = 1;
        showStep(1);
        updateProgress();
        updateScore();
    });

    // Initialize
    updateScore();
    updateLanguage();
});
