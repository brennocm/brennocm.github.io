/**
 * OSINT Dork Generator
 * Dynamic Google Dork Generator for Security Researchers
 */

// ============================================
// Dork Categories Database
// ============================================
const dorkCategories = {
    documents: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8M10 9H8"/></svg>',
        titlePt: 'Documentos Expostos',
        titleEn: 'Exposed Documents',
        descPt: 'PDFs, documentos Office e arquivos de texto',
        descEn: 'PDFs, Office documents and text files',
        dorks: [
            { name: 'PDF Files', query: 'site:{domain} filetype:pdf' },
            { name: 'Word Documents', query: 'site:{domain} filetype:doc OR filetype:docx' },
            { name: 'Excel Spreadsheets', query: 'site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv' },
            { name: 'PowerPoint', query: 'site:{domain} filetype:ppt OR filetype:pptx' },
            { name: 'Text Files', query: 'site:{domain} filetype:txt OR filetype:rtf OR filetype:odt' },
            { name: 'All Documents', query: 'site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv' }
        ]
    },
    directories: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
        titlePt: 'Listagem de Diretórios',
        titleEn: 'Directory Listing',
        descPt: 'Diretórios abertos e índices de arquivos',
        descEn: 'Open directories and file indexes',
        dorks: [
            { name: 'Index Of', query: 'site:{domain} intitle:"index of"' },
            { name: 'Parent Directory', query: 'site:{domain} intitle:"index of" "parent directory"' },
            { name: 'Apache Directory', query: 'site:{domain} intitle:"index of" "Apache"' },
            { name: 'Directory Browsing', query: 'site:{domain} "directory listing for"' }
        ]
    },
    config: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        titlePt: 'Arquivos de Configuração',
        titleEn: 'Configuration Files',
        descPt: 'Configs, env files e informações sensíveis',
        descEn: 'Configs, env files and sensitive information',
        dorks: [
            { name: 'Environment Files', query: 'site:{domain} filetype:env OR filetype:ini' },
            { name: 'Config Files', query: 'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini' },
            { name: 'PHP Info', query: 'site:{domain} ext:php intitle:phpinfo "published by the PHP Group"' },
            { name: 'htaccess', query: 'site:{domain} inurl:".htaccess" | inurl:"/.git"' },
            { name: 'Web Config', query: 'site:{domain} filetype:config OR inurl:web.config' },
            { name: 'Setup/Install Files', query: 'site:{domain} inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config' }
        ]
    },
    database: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
        titlePt: 'Arquivos de Banco de Dados',
        titleEn: 'Database Files',
        descPt: 'SQL dumps, backups e arquivos de banco',
        descEn: 'SQL dumps, backups and database files',
        dorks: [
            { name: 'SQL Files', query: 'site:{domain} ext:sql | ext:dbf | ext:mdb' },
            { name: 'Database Dumps', query: 'site:{domain} filetype:sql OR filetype:dump' },
            { name: 'SQLite Files', query: 'site:{domain} filetype:db OR filetype:sqlite' },
            { name: 'Backup Files', query: 'site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup' },
            { name: 'Log Files', query: 'site:{domain} ext:log' }
        ]
    },
    login: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        titlePt: 'Páginas de Login',
        titleEn: 'Login Pages',
        descPt: 'Painéis de admin e páginas de autenticação',
        descEn: 'Admin panels and authentication pages',
        dorks: [
            { name: 'Login Pages', query: 'site:{domain} inurl:login' },
            { name: 'Admin Panels', query: 'site:{domain} inurl:admin | inurl:administrator' },
            { name: 'Dashboard', query: 'site:{domain} inurl:dashboard | inurl:panel | inurl:portal' },
            { name: 'CPanel/Webmail', query: 'site:{domain} inurl:cpanel | inurl:webmail' },
            { name: 'User Management', query: 'site:{domain} inurl:user | inurl:account | inurl:profile' }
        ]
    },
    social: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        titlePt: 'Redes Sociais & Cloud',
        titleEn: 'Social Media & Cloud',
        descPt: 'LinkedIn, Pastebin, GitHub, S3 Buckets',
        descEn: 'LinkedIn, Pastebin, GitHub, S3 Buckets',
        dorks: [
            { name: 'LinkedIn Employees', query: 'site:linkedin.com employees "{domain}"' },
            { name: 'Pastebin Mentions', query: 'site:pastebin.com "{domain}"' },
            { name: 'GitHub Code', query: 'site:github.com "{domain}"' },
            { name: 'Trello Boards', query: 'site:trello.com "{domain}"' },
            { name: 'AWS S3 Buckets', query: 'site:s3.amazonaws.com "{domain}"' },
            { name: 'Azure Blobs', query: 'site:blob.core.windows.net "{domain}"' },
            { name: 'GitLab', query: 'site:gitlab.com "{domain}"' }
        ]
    },
    sensitive: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
        titlePt: 'Arquivos Sensíveis',
        titleEn: 'Sensitive Files',
        descPt: 'Chaves, credenciais e arquivos expostos',
        descEn: 'Keys, credentials and exposed files',
        dorks: [
            { name: 'Private Keys', query: 'site:{domain} filetype:pem OR filetype:key OR filetype:ppk' },
            { name: 'Git Repositories', query: 'site:{domain} inurl:".git" -github' },
            { name: 'Credentials', query: 'site:{domain} "password" | "passwd" | "credentials" filetype:txt' },
            { name: 'Shell/Backdoors', query: 'site:{domain} inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini' },
            { name: 'SSH Keys', query: 'site:{domain} filetype:ppk | filetype:pem | "id_rsa"' },
            { name: 'SQL Errors', query: 'site:{domain} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"' }
        ]
    },
    wordpress: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h.01M7 12l-4.5 8H10l2-6"/><path d="M17 12l4.5 8H14l-2-6"/><path d="M12 2v6l4 4"/></svg>',
        titlePt: 'WordPress',
        titleEn: 'WordPress',
        descPt: 'Arquivos e diretórios do WordPress',
        descEn: 'WordPress files and directories',
        dorks: [
            { name: 'WP Content', query: 'site:{domain} inurl:wp-content | inurl:wp-includes' },
            { name: 'WP Admin', query: 'site:{domain} inurl:wp-admin' },
            { name: 'WP Plugins', query: 'site:{domain} inurl:wp-content/plugins' },
            { name: 'WP Uploads', query: 'site:{domain} inurl:wp-content/uploads' },
            { name: 'WP Themes', query: 'site:{domain} inurl:wp-content/themes' },
            { name: 'WP Config', query: 'site:{domain} inurl:wp-config' }
        ]
    },
    subdomains: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
        titlePt: 'Subdomínios',
        titleEn: 'Subdomains',
        descPt: 'Descoberta de subdomínios via Google',
        descEn: 'Subdomain discovery via Google',
        dorks: [
            { name: 'All Subdomains', query: 'site:*.{domain}' },
            { name: 'Sub-Subdomains', query: 'site:*.*.{domain}' },
            { name: 'Exclude Main', query: 'site:*.{domain} -www' },
            { name: 'API Subdomains', query: 'site:api.{domain} | site:dev.{domain} | site:staging.{domain}' }
        ]
    },
    vulnerabilities: {
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
        titlePt: 'Potenciais Vulnerabilidades',
        titleEn: 'Potential Vulnerabilities',
        descPt: 'Sinais de vulnerabilidades comuns',
        descEn: 'Signs of common vulnerabilities',
        dorks: [
            { name: 'Open Redirects', query: 'site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http' },
            { name: 'Apache Struts', query: 'site:{domain} ext:action | ext:struts | ext:do' },
            { name: 'phpMyAdmin', query: 'site:{domain} inurl:phpmyadmin' },
            { name: 'Error Messages', query: 'site:{domain} "fatal error" | "warning:" | "error in"' },
            { name: 'Debug Pages', query: 'site:{domain} inurl:debug | inurl:test | inurl:dev' }
        ]
    }
};

// ============================================
// Internationalization
// ============================================
const i18n = {
    'pt-BR': {
        home: 'Home',
        title: 'OSINT Dork Generator',
        subtitle: 'Gere queries avançadas do Google para descobrir informações expostas em domínios',
        targetLabel: 'Domínio ou Palavra-chave Alvo',
        targetPlaceholder: 'exemplo.com.br',
        targetHint: 'Digite o domínio sem http:// ou https://',
        openGoogle: 'Abrir',
        copy: 'Copiar',
        copied: 'Copiado para a área de transferência!',
        dorksCount: 'dorks',
        guideTitle: 'Sobre Google Dorks & OSINT',
        guideIntro: 'O que são Google Dorks?',
        guideIntroText: 'Google Dorks são operadores de busca avançados que permitem encontrar informações específicas indexadas pelo Google. Eles são ferramentas essenciais para pesquisadores de segurança, pentesters e profissionais de OSINT (Open Source Intelligence).',
        guideUseCases: 'Casos de Uso',
        guideUseCase1: 'Identificar documentos sensíveis expostos publicamente',
        guideUseCase2: 'Descobrir diretórios e arquivos de configuração acessíveis',
        guideUseCase3: 'Mapear a superfície de ataque durante reconhecimento',
        guideUseCase4: 'Verificar vazamentos de credenciais e chaves de API',
        guideUseCase5: 'Encontrar painéis administrativos e páginas de login'
    },
    'en-US': {
        home: 'Home',
        title: 'OSINT Dork Generator',
        subtitle: 'Generate advanced Google queries to discover exposed information on domains',
        targetLabel: 'Target Domain or Keyword',
        targetPlaceholder: 'example.com',
        targetHint: 'Enter the domain without http:// or https://',
        openGoogle: 'Open',
        copy: 'Copy',
        copied: 'Copied to clipboard!',
        dorksCount: 'dorks',
        guideTitle: 'About Google Dorks & OSINT',
        guideIntro: 'What are Google Dorks?',
        guideIntroText: 'Google Dorks are advanced search operators that allow you to find specific information indexed by Google. They are essential tools for security researchers, pentesters, and OSINT (Open Source Intelligence) professionals.',
        guideUseCases: 'Use Cases',
        guideUseCase1: 'Identify publicly exposed sensitive documents',
        guideUseCase2: 'Discover accessible directories and configuration files',
        guideUseCase3: 'Map the attack surface during reconnaissance',
        guideUseCase4: 'Check for credential and API key leaks',
        guideUseCase5: 'Find administrative panels and login pages'
    }
};

// ============================================
// State Management
// ============================================
const state = {
    lang: 'pt-BR',
    targetDomain: '',
    expandedCategories: new Set()
};

// ============================================
// Utility Functions
// ============================================
function sanitizeDomain(input) {
    let domain = input.trim().toLowerCase();
    // Remove protocol if present
    domain = domain.replace(/^https?:\/\//, '');
    // Remove trailing slash
    domain = domain.replace(/\/$/, '');
    // Remove path if present
    domain = domain.split('/')[0];
    return domain;
}

function generateDorkQuery(template, domain) {
    if (!domain) {
        return template.replace('{domain}', 'target.com');
    }
    return template.replace(/{domain}/g, domain);
}

function buildGoogleUrl(query) {
    return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

// ============================================
// UI Rendering Functions
// ============================================
function renderCategories() {
    const container = document.getElementById('categoriesGrid');
    if (!container) return;

    container.innerHTML = '';
    const lang = state.lang;

    Object.entries(dorkCategories).forEach(([key, category]) => {
        const isExpanded = state.expandedCategories.has(key);
        const title = lang === 'pt-BR' ? category.titlePt : category.titleEn;
        const desc = lang === 'pt-BR' ? category.descPt : category.descEn;

        const card = document.createElement('div');
        card.className = `category-card ${isExpanded ? 'expanded' : ''}`;
        card.dataset.category = key;

        card.innerHTML = `
            <div class="category-header" onclick="toggleCategory('${key}')">
                <div class="category-info">
                    <div class="category-icon ${key}">${category.icon}</div>
                    <div class="category-title">
                        <h3>${title}</h3>
                        <span>${category.dorks.length} ${i18n[lang].dorksCount}</span>
                    </div>
                </div>
                <div class="category-toggle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M6 9l6 6 6-6"/>
                    </svg>
                </div>
            </div>
            <div class="category-content">
                <div class="dorks-list">
                    ${renderDorks(category.dorks)}
                </div>
            </div>
        `;

        container.appendChild(card);
    });
}

function renderDorks(dorks) {
    const lang = state.lang;
    const domain = state.targetDomain || 'target.com';

    return dorks.map((dork, index) => {
        const query = generateDorkQuery(dork.query, state.targetDomain);
        const displayQuery = highlightDomain(query, domain);

        return `
            <div class="dork-item">
                <div class="dork-header">
                    <span class="dork-name">${dork.name}</span>
                    <div class="dork-actions">
                        <button class="dork-btn open" onclick="openInGoogle('${escapeHtml(query)}')" title="${i18n[lang].openGoogle}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
                                <path d="M15 3h6v6"/>
                                <path d="M10 14L21 3"/>
                            </svg>
                            ${i18n[lang].openGoogle}
                        </button>
                        <button class="dork-btn copy" onclick="copyToClipboard('${escapeHtml(query)}')" title="${i18n[lang].copy}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2"/>
                                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                            </svg>
                            ${i18n[lang].copy}
                        </button>
                    </div>
                </div>
                <div class="dork-query">${displayQuery}</div>
            </div>
        `;
    }).join('');
}

function highlightDomain(query, domain) {
    if (!domain || domain === 'target.com') {
        return escapeHtml(query).replace(/target\.com/g, '<span class="domain-placeholder">target.com</span>');
    }
    return escapeHtml(query).replace(new RegExp(escapeRegExp(domain), 'g'), `<span class="domain-placeholder">${domain}</span>`);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function updateDorks() {
    // Re-render all dorks with the new domain
    document.querySelectorAll('.category-card').forEach(card => {
        const key = card.dataset.category;
        const category = dorkCategories[key];
        const dorksList = card.querySelector('.dorks-list');
        if (dorksList && category) {
            dorksList.innerHTML = renderDorks(category.dorks);
        }
    });
}

// ============================================
// Event Handlers
// ============================================
function toggleCategory(key) {
    if (state.expandedCategories.has(key)) {
        state.expandedCategories.delete(key);
    } else {
        state.expandedCategories.add(key);
    }

    const card = document.querySelector(`.category-card[data-category="${key}"]`);
    if (card) {
        card.classList.toggle('expanded');
    }
}

function openInGoogle(query) {
    if (!state.targetDomain) {
        const input = document.getElementById('targetInput');
        if (input) {
            input.focus();
            input.classList.add('input-error');
            setTimeout(() => input.classList.remove('input-error'), 500);

            // Show toast feedback for error
            const feedback = document.getElementById('copyFeedback');
            if (feedback) {
                // Save original text and icon
                const originalText = feedback.querySelector('span').textContent;
                const originalIcon = feedback.querySelector('svg').innerHTML;

                // Update for error
                feedback.querySelector('span').textContent = state.lang === 'pt-BR' ? 'Digite um domínio alvo primeiro!' : 'Enter a target domain first!';
                feedback.querySelector('svg').innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
                feedback.style.background = '#ff4444';
                feedback.style.color = '#fff';

                feedback.classList.add('show');

                setTimeout(() => {
                    feedback.classList.remove('show');
                    // Restore after animation
                    setTimeout(() => {
                        feedback.querySelector('span').textContent = originalText;
                        feedback.querySelector('svg').innerHTML = originalIcon;
                        feedback.style.background = '';
                        feedback.style.color = '';
                    }, 300);
                }, 2500);
            }
        }
        return;
    }
    const url = buildGoogleUrl(query);
    window.open(url, '_blank', 'noopener,noreferrer');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showCopyFeedback();
    }).catch(err => {
        console.error('Failed to copy:', err);
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showCopyFeedback();
    });
}

function showCopyFeedback() {
    const feedback = document.getElementById('copyFeedback');
    if (feedback) {
        feedback.classList.add('show');
        setTimeout(() => {
            feedback.classList.remove('show');
        }, 2500);
    }
}

function handleTargetInput(event) {
    const input = event.target.value;
    state.targetDomain = sanitizeDomain(input);
    updateDorks();
}

function updateLanguage() {
    const lang = i18n[state.lang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (lang[key]) {
            el.textContent = lang[key];
        }
    });

    // Update placeholder
    const targetInput = document.getElementById('targetInput');
    if (targetInput) {
        targetInput.placeholder = lang.targetPlaceholder;
    }
}

// ============================================
// Initialization
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Detect language from HTML attribute
    const htmlLang = document.documentElement.getAttribute('data-lang');
    if (htmlLang) {
        state.lang = htmlLang;
    }

    // Initialize categories
    renderCategories();

    // Update language strings
    updateLanguage();

    // Target input listener with debounce
    const targetInput = document.getElementById('targetInput');
    if (targetInput) {
        let debounceTimer;
        targetInput.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => handleTargetInput(e), 150);
        });
    }
});
