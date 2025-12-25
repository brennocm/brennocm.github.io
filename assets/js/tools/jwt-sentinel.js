// ============================================
// JWT Sentinel - JWT Decoder Tool
// ============================================

// ============================================
// Internationalization
// ============================================
const i18n = {
    'pt-BR': {
        title: 'JWT Sentinel',
        subtitle: 'Decodifique e analise tokens JWT com segurança',
        privacyBadge: 'Seu token nunca sai do navegador. Processamento 100% local.',
        inputLabel: 'Cole seu token JWT aqui',
        inputPlaceholder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        decodeBtn: 'Decodificar',
        clearBtn: 'Limpar',
        copyBtn: 'Copiar',
        header: 'Header',
        payload: 'Payload',
        signature: 'Assinatura',
        claimsAnalysis: 'Análise de Claims',
        validToken: 'Token válido (estrutura correta)',
        invalidToken: 'Token inválido',
        expiredToken: 'Token expirado',
        notExpired: 'Token não expirado',
        signatureNote: 'A assinatura não pode ser verificada sem a chave secreta.',
        algorithm: 'Algoritmo',
        type: 'Tipo',
        issuedAt: 'Emitido em',
        expiresAt: 'Expira em',
        notBefore: 'Válido a partir de',
        issuer: 'Emissor',
        subject: 'Assunto',
        audience: 'Audiência',
        jwtId: 'JWT ID',
        copied: 'Copiado!',
        guideTitle: 'Guia: O que é JWT?',
        guideIntro: 'O que é um JSON Web Token?',
        guideIntroText: 'JWT (JSON Web Token) é um padrão aberto (RFC 7519) que define uma forma compacta e autossuficiente de transmitir informações entre partes como um objeto JSON. Essas informações podem ser verificadas e confiáveis porque são assinadas digitalmente.',
        guideStructure: 'Estrutura do JWT',
        guideStructureText: 'Um JWT consiste em três partes separadas por pontos:',
        guideHeaderDesc: 'Contém o tipo do token e o algoritmo de assinatura',
        guidePayloadDesc: 'Contém as claims (declarações) sobre a entidade',
        guideSignatureDesc: 'Usado para verificar a integridade do token',
        guideSecurity: 'Considerações de Segurança',
        guideSecurityItems: [
            'JWTs são codificados, não criptografados - qualquer um pode ler o conteúdo',
            'Nunca armazene informações sensíveis no payload',
            'Sempre valide a assinatura no servidor',
            'Use HTTPS para transmitir tokens',
            'Defina tempos de expiração curtos quando possível'
        ]
    },
    'en-US': {
        title: 'JWT Sentinel',
        subtitle: 'Decode and analyze JWT tokens securely',
        privacyBadge: 'Your token never leaves your browser. 100% local processing.',
        inputLabel: 'Paste your JWT token here',
        inputPlaceholder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        decodeBtn: 'Decode',
        clearBtn: 'Clear',
        copyBtn: 'Copy',
        header: 'Header',
        payload: 'Payload',
        signature: 'Signature',
        claimsAnalysis: 'Claims Analysis',
        validToken: 'Valid token (correct structure)',
        invalidToken: 'Invalid token',
        expiredToken: 'Token expired',
        notExpired: 'Token not expired',
        signatureNote: 'The signature cannot be verified without the secret key.',
        algorithm: 'Algorithm',
        type: 'Type',
        issuedAt: 'Issued at',
        expiresAt: 'Expires at',
        notBefore: 'Valid from',
        issuer: 'Issuer',
        subject: 'Subject',
        audience: 'Audience',
        jwtId: 'JWT ID',
        copied: 'Copied!',
        guideTitle: 'Guide: What is JWT?',
        guideIntro: 'What is a JSON Web Token?',
        guideIntroText: 'JWT (JSON Web Token) is an open standard (RFC 7519) that defines a compact and self-contained way of securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.',
        guideStructure: 'JWT Structure',
        guideStructureText: 'A JWT consists of three parts separated by dots:',
        guideHeaderDesc: 'Contains the token type and signing algorithm',
        guidePayloadDesc: 'Contains the claims (statements) about the entity',
        guideSignatureDesc: 'Used to verify the integrity of the token',
        guideSecurity: 'Security Considerations',
        guideSecurityItems: [
            'JWTs are encoded, not encrypted - anyone can read the contents',
            'Never store sensitive information in the payload',
            'Always validate the signature on the server',
            'Use HTTPS to transmit tokens',
            'Set short expiration times when possible'
        ]
    }
};

// ============================================
// State
// ============================================
const state = {
    lang: document.documentElement.getAttribute('data-lang') || 'pt-BR',
    decodedToken: null
};

// ============================================
// Utility Functions
// ============================================

// Base64URL decode (JWT uses URL-safe Base64)
function base64UrlDecode(str) {
    // Replace URL-safe characters
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const padding = base64.length % 4;
    if (padding) {
        base64 += '='.repeat(4 - padding);
    }

    try {
        // Decode Base64
        const decoded = atob(base64);
        // Convert to UTF-8
        return decodeURIComponent(
            decoded.split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
        );
    } catch (e) {
        throw new Error('Invalid Base64 encoding');
    }
}

// Parse JWT
function parseJWT(token) {
    const parts = token.trim().split('.');

    if (parts.length !== 3) {
        throw new Error('Invalid JWT format: must have 3 parts');
    }

    const [headerB64, payloadB64, signature] = parts;

    let header, payload;

    try {
        header = JSON.parse(base64UrlDecode(headerB64));
    } catch (e) {
        throw new Error('Invalid header: ' + e.message);
    }

    try {
        payload = JSON.parse(base64UrlDecode(payloadB64));
    } catch (e) {
        throw new Error('Invalid payload: ' + e.message);
    }

    return {
        header,
        payload,
        signature,
        raw: {
            header: headerB64,
            payload: payloadB64,
            signature
        }
    };
}

// Check if token is expired
function isTokenExpired(payload) {
    if (!payload.exp) return null;
    const now = Math.floor(Date.now() / 1000);
    return now > payload.exp;
}

// Format timestamp to readable date
function formatTimestamp(timestamp) {
    if (!timestamp) return null;
    const date = new Date(timestamp * 1000);
    return date.toLocaleString(state.lang === 'pt-BR' ? 'pt-BR' : 'en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// Syntax highlight JSON
function syntaxHighlightJSON(json) {
    const str = JSON.stringify(json, null, 2);
    return str.replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
        match => {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                    match = match.replace(/:$/, '');
                    return `<span class="${cls}">${escapeHtml(match)}</span>:`;
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return `<span class="${cls}">${escapeHtml(match)}</span>`;
        }
    );
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// UI Functions
// ============================================

function decodeToken() {
    const input = document.getElementById('jwtInput');
    const token = input.value.trim();

    if (!token) {
        showError('Por favor, insira um token JWT');
        return;
    }

    try {
        state.decodedToken = parseJWT(token);
        renderResults();
    } catch (e) {
        showError(e.message);
    }
}

function showError(message) {
    const lang = i18n[state.lang];
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.classList.add('visible');

    resultsSection.innerHTML = `
        <div class="status-banner invalid">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            <span>${lang.invalidToken}: ${escapeHtml(message)}</span>
        </div>
    `;
}

function renderResults() {
    const lang = i18n[state.lang];
    const { header, payload, signature } = state.decodedToken;
    const expired = isTokenExpired(payload);

    const resultsSection = document.getElementById('resultsSection');
    resultsSection.classList.add('visible');

    // Determine status
    let statusClass = 'valid';
    let statusText = lang.validToken;
    let statusIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
        <polyline points="22 4 12 14.01 9 11.01"/>
    </svg>`;

    if (expired === true) {
        statusClass = 'expired';
        statusText = lang.expiredToken;
        statusIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
        </svg>`;
    }

    // Build claims analysis
    const claims = buildClaimsAnalysis(header, payload);

    // Copy button SVG
    const copyIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="9" y="9" width="13" height="13" rx="2"/>
        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
    </svg>`;

    resultsSection.innerHTML = `
        <div class="status-banner ${statusClass}">
            ${statusIcon}
            <span>${statusText}</span>
        </div>
        
        <div class="jwt-parts-grid">
            <!-- Header Card -->
            <div class="result-card">
                <div class="result-card-header">
                    <div class="result-card-icon header-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                            <path d="M14 2v6h6"/>
                            <path d="M16 13H8M16 17H8M10 9H8"/>
                        </svg>
                    </div>
                    <span class="result-card-title">${lang.header}</span>
                    <button class="copy-btn" data-copy="header" title="${lang.copyBtn}">
                        ${copyIcon}
                    </button>
                </div>
                <div class="result-card-content">
                    <div class="json-display">${syntaxHighlightJSON(header)}</div>
                </div>
            </div>
            
            <!-- Payload Card -->
            <div class="result-card">
                <div class="result-card-header">
                    <div class="result-card-icon payload-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
                            <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
                            <line x1="12" y1="22.08" x2="12" y2="12"/>
                        </svg>
                    </div>
                    <span class="result-card-title">${lang.payload}</span>
                    <button class="copy-btn" data-copy="payload" title="${lang.copyBtn}">
                        ${copyIcon}
                    </button>
                </div>
                <div class="result-card-content">
                    <div class="json-display">${syntaxHighlightJSON(payload)}</div>
                </div>
            </div>
            
            <!-- Signature Card -->
            <div class="result-card full-width">
                <div class="result-card-header">
                    <div class="result-card-icon signature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                    </div>
                    <span class="result-card-title">${lang.signature}</span>
                    <button class="copy-btn" data-copy="signature" title="${lang.copyBtn}">
                        ${copyIcon}
                    </button>
                </div>
                <div class="result-card-content">
                    <div class="signature-display">${escapeHtml(signature)}</div>
                    <div class="signature-note">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        <span>${lang.signatureNote}</span>
                    </div>
                </div>
            </div>
            
            <!-- Claims Analysis Card -->
            <div class="result-card full-width">
                <div class="result-card-header">
                    <div class="result-card-icon claims-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="8" y1="6" x2="21" y2="6"/>
                            <line x1="8" y1="12" x2="21" y2="12"/>
                            <line x1="8" y1="18" x2="21" y2="18"/>
                            <line x1="3" y1="6" x2="3.01" y2="6"/>
                            <line x1="3" y1="12" x2="3.01" y2="12"/>
                            <line x1="3" y1="18" x2="3.01" y2="18"/>
                        </svg>
                    </div>
                    <span class="result-card-title">${lang.claimsAnalysis}</span>
                </div>
                <div class="result-card-content">
                    <div class="claims-list">
                        ${claims}
                    </div>
                </div>
            </div>
        </div>
    `;

    // Add event listeners for copy buttons
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-copy');
            let content = '';
            if (type === 'header') {
                content = JSON.stringify(state.decodedToken.header, null, 2);
            } else if (type === 'payload') {
                content = JSON.stringify(state.decodedToken.payload, null, 2);
            } else if (type === 'signature') {
                content = state.decodedToken.signature;
            }
            copyToClipboard(content);
        });
    });
}

function buildClaimsAnalysis(header, payload) {
    const lang = i18n[state.lang];
    const claims = [];

    // Algorithm
    if (header.alg) {
        claims.push({
            label: lang.algorithm,
            code: 'alg',
            value: header.alg
        });
    }

    // Type
    if (header.typ) {
        claims.push({
            label: lang.type,
            code: 'typ',
            value: header.typ
        });
    }

    // Issuer
    if (payload.iss) {
        claims.push({
            label: lang.issuer,
            code: 'iss',
            value: payload.iss
        });
    }

    // Subject
    if (payload.sub) {
        claims.push({
            label: lang.subject,
            code: 'sub',
            value: payload.sub
        });
    }

    // Audience
    if (payload.aud) {
        claims.push({
            label: lang.audience,
            code: 'aud',
            value: Array.isArray(payload.aud) ? payload.aud.join(', ') : payload.aud
        });
    }

    // Issued At
    if (payload.iat) {
        claims.push({
            label: lang.issuedAt,
            code: 'iat',
            value: formatTimestamp(payload.iat)
        });
    }

    // Expires At
    if (payload.exp) {
        const expired = isTokenExpired(payload);
        claims.push({
            label: lang.expiresAt,
            code: 'exp',
            value: formatTimestamp(payload.exp),
            status: expired ? 'expired' : 'valid'
        });
    }

    // Not Before
    if (payload.nbf) {
        claims.push({
            label: lang.notBefore,
            code: 'nbf',
            value: formatTimestamp(payload.nbf)
        });
    }

    // JWT ID
    if (payload.jti) {
        claims.push({
            label: lang.jwtId,
            code: 'jti',
            value: payload.jti
        });
    }

    return claims.map(claim => `
        <div class="claim-item">
            <div class="claim-label">
                <span>${claim.label}</span>
                <code>${claim.code}</code>
            </div>
            <div class="claim-value ${claim.status || ''}">${escapeHtml(claim.value)}</div>
        </div>
    `).join('');
}

function clearInput() {
    document.getElementById('jwtInput').value = '';
    document.getElementById('resultsSection').classList.remove('visible');
    document.getElementById('resultsSection').innerHTML = '';
    state.decodedToken = null;
}

function copyToClipboard(text) {
    const lang = i18n[state.lang];
    navigator.clipboard.writeText(text).then(() => {
        showCopyFeedback();
    });
}

function showCopyFeedback() {
    const feedback = document.getElementById('copyFeedback');
    feedback.classList.add('show');
    setTimeout(() => {
        feedback.classList.remove('show');
    }, 2000);
}

// ============================================
// Event Listeners
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // Decode button
    const decodeBtn = document.getElementById('decodeBtn');
    if (decodeBtn) {
        decodeBtn.addEventListener('click', decodeToken);
    }

    // Clear button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearInput);
    }

    // Input - decode on paste
    const jwtInput = document.getElementById('jwtInput');
    if (jwtInput) {
        jwtInput.addEventListener('paste', () => {
            setTimeout(decodeToken, 100);
        });

        // Decode on Enter (Ctrl+Enter for multiline)
        jwtInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                decodeToken();
            }
        });
    }
});
