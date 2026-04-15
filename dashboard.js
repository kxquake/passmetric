/**
 * PassMetric Dashboard — Main Controller
 * Depends on: api.js (API helper, showToast, strengthColor, strengthName, copyToClipboard)
 */

(function () {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════════════════
    const state = {
        user: null,
        entries: [],          // vault entries (decrypted by backend)
        audit: null,          // health audit results
        currentPage: 'overview',
        editingEntryId: null, // null = add mode, string = edit mode
        deleteEntryId: null,
    };


    // ═══════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════════

    /** Render an SVG score ring */
    function renderScoreRing(container, score, size, strokeWidth) {
        size = size || 140;
        strokeWidth = strokeWidth || 10;
        const r = (size - strokeWidth) / 2;
        const circ = 2 * Math.PI * r;
        const offset = circ - (score / 100) * circ;
        const color = strengthColor(score);

        container.innerHTML = `
            <svg width="${size}" height="${size}" style="transform:rotate(-90deg)">
                <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none"
                    stroke="rgba(255,255,255,0.06)" stroke-width="${strokeWidth}"/>
                <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none"
                    stroke="${color}" stroke-width="${strokeWidth}"
                    stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
                    stroke-linecap="round"
                    style="transition:stroke-dashoffset 1s ease, stroke 0.5s ease"/>
                <text x="${size/2}" y="${size/2}" fill="white"
                    font-size="${size*0.28}" font-weight="700"
                    text-anchor="middle" dominant-baseline="central"
                    style="transform:rotate(90deg);transform-origin:center">
                    ${Math.round(score)}
                </text>
            </svg>`;
    }

    /** Create a strength bar HTML string */
    function strengthBarHTML(score) {
        const color = strengthColor(score);
        return `
            <div class="strength-bar-wrap">
                <div class="strength-bar-track">
                    <div class="strength-bar-fill" style="width:${score}%;background:${color}"></div>
                </div>
                <span class="strength-bar-score" style="color:${color}">${Math.round(score)}</span>
            </div>`;
    }

    /** Quick strength label */
    function strengthLabelText(score) {
        if (score >= 80) return 'Very Strong';
        if (score >= 60) return 'Strong';
        if (score >= 40) return 'Medium';
        if (score >= 20) return 'Weak';
        return 'Very Weak';
    }

    /** Show / hide elements */
    function show(el) { el.classList.remove('hidden'); }
    function hide(el) { el.classList.add('hidden'); }

    /** Quick DOM access */
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);


    // ═══════════════════════════════════════════════════════════════════
    //  TOAST  (enhanced version — works with api.js showToast fallback)
    // ═══════════════════════════════════════════════════════════════════
    function toast(msg, type) {
        type = type || 'success';
        const el = $('#toast');
        el.textContent = msg;
        el.className = 'toast ' + type + ' show';
        clearTimeout(el._t);
        el._t = setTimeout(() => {
            el.classList.remove('show');
            el.classList.add('hide');
        }, 2500);
    }


    // ═══════════════════════════════════════════════════════════════════
    //  NAVIGATION
    // ═══════════════════════════════════════════════════════════════════
    function navigateTo(page) {
        state.currentPage = page;

        // Toggle active nav button
        $$('.nav-btn[data-page]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.page === page);
        });

        // Toggle active page section
        $$('.page').forEach(p => {
            p.classList.toggle('active', p.id === 'page-' + page);
        });

        // Lazy-render pages
        if (page === 'overview')  renderOverview();
        if (page === 'vault')     renderVault();
        if (page === 'health')    renderHealthAudit();
        if (page === 'settings')  renderSettings();
    }


    // ═══════════════════════════════════════════════════════════════════
    //  DATA LOADING
    // ═══════════════════════════════════════════════════════════════════
    async function loadUser() {
        try {
            const data = await API.get('/auth/me');
            state.user = data;
            $('#user-email').textContent = data.email;
            $('#user-avatar').textContent = data.email.charAt(0).toUpperCase();
        } catch (err) {
            // Session expired — redirect handled by api.js
            console.warn('Could not load user:', err);
        }
    }

    async function loadVaultEntries() {
        try {
            const data = await API.get('/vault/entries');
            // Server returns { entries: [...] }
            const raw = data.entries || [];

            // Enrich each entry with a quick client-side score estimate
            // (the real score comes from /analyze, but we want instant rendering)
            state.entries = raw.map(e => ({
                ...e,
                score: e.score ?? estimateScore(e.password),
            }));
        } catch (err) {
            console.warn('Could not load vault:', err);
            state.entries = [];
        }
    }

    async function loadHealthAudit() {
        try {
            state.audit = await API.get('/tools/health-audit');
        } catch (err) {
            console.warn('Could not load audit:', err);
            // Build a basic fallback from loaded entries
            const scores = state.entries.map(e => e.score);
            const avg = scores.length ? scores.reduce((a,b) => a + b, 0) / scores.length : 0;
            state.audit = {
                average_score: Math.round(avg * 10) / 10,
                total: state.entries.length,
                weak_count: scores.filter(s => s < 40).length,
                entries: state.entries.map(e => ({
                    website: e.website,
                    username: e.username,
                    score: e.score,
                    strength: e.score >= 80 ? 'very_strong' : e.score >= 60 ? 'strong' : e.score >= 40 ? 'medium' : 'weak',
                })),
            };
        }
    }

    /** Quick client-side score estimate for instant rendering */
    function estimateScore(pwd) {
        if (!pwd) return 0;
        let s = 0;
        if (pwd.length >= 8)  s += 15;
        if (pwd.length >= 12) s += 15;
        if (pwd.length >= 16) s += 10;
        if (/[a-z]/.test(pwd)) s += 10;
        if (/[A-Z]/.test(pwd)) s += 10;
        if (/\d/.test(pwd))    s += 10;
        if (/[^a-zA-Z0-9]/.test(pwd)) s += 15;
        if (new Set(pwd).size / pwd.length > 0.7) s += 15;
        return Math.min(100, s);
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: OVERVIEW
    // ═══════════════════════════════════════════════════════════════════
    function renderOverview() {
        const entries = state.entries;
        const audit = state.audit;
        if (!audit) return;

        const weak   = entries.filter(e => e.score < 40).length;
        const strong = entries.filter(e => e.score >= 80).length;
        const medium = entries.length - weak - strong;

        // Stats cards
        const stats = [
            { label: 'Total Passwords', value: entries.length, icon: 'vault',   color: '#6366f1' },
            { label: 'Average Score',   value: audit.average_score, icon: 'shield', color: strengthColor(audit.average_score) },
            { label: 'Weak Passwords',  value: weak,  icon: 'warning', color: '#f97316' },
            { label: 'Strong Passwords',value: strong, icon: 'check',  color: '#22c55e' },
        ];
        const iconPaths = {
            vault:   'M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z',
            shield:  'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z',
            warning: 'M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z',
            check:   'M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z',
        };

        $('#overview-stats').innerHTML = stats.map(s => `
            <div class="stat-card">
                <div class="stat-icon" style="background:${s.color}18;color:${s.color}">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="${iconPaths[s.icon]}"/></svg>
                </div>
                <div>
                    <div class="stat-value">${s.value}</div>
                    <div class="stat-label">${s.label}</div>
                </div>
            </div>`).join('');

        // Score ring
        renderScoreRing($('#overview-ring'), audit.average_score, 140, 10);
        const ringLabel = $('#overview-ring-label');
        ringLabel.textContent = strengthLabelText(audit.average_score);
        ringLabel.style.color = strengthColor(audit.average_score);

        // Distribution
        const dist = [
            { label: 'Strong (80+)',   count: strong, color: '#22c55e', pct: entries.length ? (strong / entries.length) * 100 : 0 },
            { label: 'Medium (40–79)', count: medium, color: '#eab308', pct: entries.length ? (medium / entries.length) * 100 : 0 },
            { label: 'Weak (0–39)',    count: weak,   color: '#ef4444', pct: entries.length ? (weak / entries.length) * 100 : 0 },
        ];
        $('#overview-distribution').innerHTML = dist.map(d => `
            <div class="dist-row">
                <div class="dist-row-header">
                    <span class="dist-row-label">${d.label}</span>
                    <span class="dist-row-count" style="color:${d.color}">${d.count}</span>
                </div>
                <div class="dist-bar-track">
                    <div class="dist-bar-fill" style="width:${d.pct}%;background:${d.color}"></div>
                </div>
            </div>`).join('');

        const alert = $('#overview-alert');
        if (weak > 0) {
            alert.className = 'alert-box danger';
            alert.textContent = `${weak} password${weak > 1 ? 's' : ''} need${weak === 1 ? 's' : ''} attention`;
        } else {
            alert.className = 'alert-box success';
            alert.textContent = 'All passwords are in good shape!';
        }
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: VAULT
    // ═══════════════════════════════════════════════════════════════════
    const revealedIds = new Set();
    let copiedTimeout = null;

    function renderVault(filter) {
        filter = (filter || '').toLowerCase();
        const entries = state.entries.filter(e =>
            e.website.toLowerCase().includes(filter) ||
            e.username.toLowerCase().includes(filter)
        );

        $('#vault-count').textContent = state.entries.length + ' stored credentials';

        if (entries.length === 0) {
            $('#vault-list').innerHTML = `<div class="entry-empty">${
                filter ? 'No entries match your search' : 'Your vault is empty. Add your first password!'
            }</div>`;
            return;
        }

        $('#vault-list').innerHTML = entries.map(entry => {
            const c = strengthColor(entry.score);
            const revealed = revealedIds.has(entry.entry_id);
            return `
            <div class="entry-row" data-id="${entry.entry_id}">
                <div class="entry-favicon" style="background:${c}12;color:${c}">
                    ${entry.website.charAt(0).toUpperCase()}
                </div>
                <div class="entry-info">
                    <div class="entry-website">${esc(entry.website)}</div>
                    <div class="entry-username">${esc(entry.username)}</div>
                </div>
                <div class="entry-password">${revealed ? esc(entry.password) : '••••••••••••'}</div>
                <div class="entry-score">${strengthBarHTML(entry.score)}</div>
                <div class="entry-actions">
                    <button title="${revealed ? 'Hide' : 'Reveal'}" data-action="reveal" data-id="${entry.entry_id}">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                            ${revealed
                                ? '<path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>'
                                : '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>'}
                        </svg>
                    </button>
                    <button title="Copy" data-action="copy" data-id="${entry.entry_id}">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                    </button>
                    <button title="Edit" data-action="edit" data-id="${entry.entry_id}">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                    </button>
                    <button title="Delete" data-action="delete" data-id="${entry.entry_id}">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                    </button>
                </div>
            </div>`;
        }).join('');
    }

    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: GENERATOR
    // ═══════════════════════════════════════════════════════════════════
    let generatorMode = 'password';

    async function generatePassword() {
        const length = +$('#gen-length').value;
        const opts = {
            length,
            include_uppercase: $('#gen-upper').checked,
            include_lowercase: $('#gen-lower').checked,
            include_digits:    $('#gen-digits').checked,
            include_special:   $('#gen-symbols').checked,
        };

        try {
            const data = await API.post('/generate', { requirements: opts });
            const pwd = data.password;
            $('#gen-output').textContent = pwd;

            // Analyze it for a score
            try {
                const analysis = await API.post('/analyze', { password: pwd });
                const score = analysis.rule_based?.score ?? estimateScore(pwd);
                updateGenStrength(score);
            } catch {
                updateGenStrength(estimateScore(pwd));
            }
        } catch (err) {
            // Fallback: client-side generation
            clientGeneratePassword(opts);
        }
    }

    function clientGeneratePassword(opts) {
        const chars = [
            opts.include_lowercase !== false ? 'abcdefghijklmnopqrstuvwxyz' : '',
            opts.include_uppercase !== false ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '',
            opts.include_digits !== false    ? '0123456789' : '',
            opts.include_special !== false   ? '!@#$%^&*()_+-=[]{}|;:,.<>?' : '',
        ].join('');
        if (!chars) { toast('Select at least one character type', 'error'); return; }
        const arr = new Uint32Array(opts.length || 16);
        crypto.getRandomValues(arr);
        let pwd = '';
        for (let i = 0; i < arr.length; i++) pwd += chars[arr[i] % chars.length];
        $('#gen-output').textContent = pwd;
        updateGenStrength(estimateScore(pwd));
    }

    async function generatePassphrase() {
        const wordCount  = +$('#gen-words').value;
        const separator  = $('#gen-separator').value;
        const capitalize = $('#gen-capitalize').checked;
        const addNumber  = $('#gen-addnum').checked;

        try {
            const data = await API.post('/tools/generate-passphrase', {
                word_count: wordCount, separator, capitalize, add_number: addNumber,
            });
            const phrase = data.passphrase;
            $('#gen-output').textContent = phrase;
            const score = data.analysis?.rule_based?.score ?? estimateScore(phrase);
            updateGenStrength(score);
        } catch {
            // Fallback: client-side
            clientGeneratePassphrase(wordCount, separator, capitalize, addNumber);
        }
    }

    function clientGeneratePassphrase(count, sep, cap, num) {
        const words = ['correct','horse','battery','staple','sunset','ocean','crystal','thunder','falcon','marble',
            'garden','silver','phoenix','dragon','violet','ember','cascade','summit','anchor','breeze',
            'coral','eclipse','horizon','jasmine','lunar','meadow','nebula','orchid','prism','quartz'];
        const arr = new Uint32Array(count);
        crypto.getRandomValues(arr);
        let parts = [];
        for (let i = 0; i < count; i++) {
            let w = words[arr[i] % words.length];
            if (cap) w = w.charAt(0).toUpperCase() + w.slice(1);
            parts.push(w);
        }
        let result = parts.join(sep);
        if (num) result += sep + (100 + Math.floor(Math.random() * 900));
        $('#gen-output').textContent = result;
        updateGenStrength(estimateScore(result));
    }

    function updateGenStrength(score) {
        const color = strengthColor(score);
        $('#gen-strength-bar').innerHTML = strengthBarHTML(score);
        const label = $('#gen-strength-label');
        label.textContent = strengthLabelText(score);
        label.style.color = color;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: ANALYZER
    // ═══════════════════════════════════════════════════════════════════
    async function analyzePassword() {
        const pwd = $('#analyzer-input').value.trim();
        if (!pwd) { toast('Enter a password first', 'error'); return; }

        let analysis;
        try {
            analysis = await API.post('/analyze', { password: pwd });
        } catch {
            // Client-side fallback
            analysis = clientAnalyze(pwd);
        }

        const rule = analysis.rule_based || analysis;
        const score = rule.score ?? 0;

        show($('#analyzer-results'));

        // Ring
        renderScoreRing($('#analyzer-ring'), score, 140, 10);
        const ringLabel = $('#analyzer-ring-label');
        ringLabel.textContent = strengthLabelText(score);
        ringLabel.style.color = strengthColor(score);

        // Stats
        $('#analyzer-stats').innerHTML = [
            { label: 'Entropy',  value: (rule.entropy_bits ?? 0).toFixed(1) + ' bits' },
            { label: 'Length',   value: pwd.length },
            { label: 'Unique',   value: rule.character_diversity ?? new Set(pwd).size },
            { label: 'Types',    value: (rule.types_count ?? countTypes(pwd)) + '/4' },
        ].map(s => `
            <div class="analyzer-stat">
                <div class="analyzer-stat-val">${s.value}</div>
                <div class="analyzer-stat-lbl">${s.label}</div>
            </div>`).join('');

        // Feedback
        let fb = '';
        const issues = rule.issues || [];
        const warnings = rule.warnings || [];
        const recs = rule.recommendations || [];

        if (issues.length) fb += `
            <div class="feedback-block issues">
                <div class="feedback-title issues">Critical Issues</div>
                ${issues.map(i => `<div class="feedback-item">• ${esc(i)}</div>`).join('')}
            </div>`;
        if (warnings.length) fb += `
            <div class="feedback-block warnings">
                <div class="feedback-title warnings">Warnings</div>
                ${warnings.map(w => `<div class="feedback-item">• ${esc(w)}</div>`).join('')}
            </div>`;
        if (recs.length) fb += `
            <div class="feedback-block recs">
                <div class="feedback-title recs">Recommendations</div>
                ${recs.map(r => `<div class="feedback-item">• ${esc(r)}</div>`).join('')}
            </div>`;
        if (!fb) fb = '<div class="feedback-block recs"><div class="feedback-title recs">Looking good!</div><div class="feedback-item">No issues detected.</div></div>';

        $('#analyzer-feedback').innerHTML = fb;
    }

    function countTypes(pwd) {
        return [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter(r => r.test(pwd)).length;
    }

    function clientAnalyze(pwd) {
        const len = pwd.length;
        const hasLower = /[a-z]/.test(pwd), hasUpper = /[A-Z]/.test(pwd);
        const hasDigit = /\d/.test(pwd), hasSymbol = /[^a-zA-Z0-9]/.test(pwd);
        const types = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
        let cs = 0;
        if (hasLower) cs += 26; if (hasUpper) cs += 26; if (hasDigit) cs += 10; if (hasSymbol) cs += 32;
        const entropy = cs > 0 ? Math.log2(cs) * len : 0;
        let score = Math.min(100, (entropy / 128) * 100);
        if (len < 8) score *= 0.3; else if (len < 12) score *= 0.6; else if (len >= 16) score *= 1.1;
        score = Math.min(100, Math.max(0, score));

        const issues = [], warnings = [], recs = [];
        if (len < 8)    issues.push('Password is too short (minimum 8 characters)');
        if (!hasUpper)   warnings.push('Add uppercase letters for more strength');
        if (!hasDigit)   warnings.push('Include digits to increase complexity');
        if (!hasSymbol)  warnings.push('Special characters significantly improve security');
        if (types < 3)   recs.push('Use at least 3 character types');
        if (len < 16)    recs.push('Consider using 16+ characters');

        return {
            rule_based: {
                score: Math.round(score * 10) / 10,
                entropy_bits: Math.round(entropy * 100) / 100,
                character_diversity: new Set(pwd).size,
                types_count: types,
                issues, warnings, recommendations: recs,
            }
        };
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: HEALTH AUDIT
    // ═══════════════════════════════════════════════════════════════════
    function renderHealthAudit() {
        const audit = state.audit;
        if (!audit) return;

        $('#health-stats').innerHTML = [
            { label: 'Average Score',   value: audit.average_score, color: strengthColor(audit.average_score) },
            { label: 'Total Entries',   value: audit.total,         color: '#6366f1' },
            { label: 'Weak Passwords',  value: audit.weak_count,    color: audit.weak_count > 0 ? '#ef4444' : '#22c55e' },
        ].map(s => `
            <div class="stat-card" style="justify-content:center; flex-direction:column; align-items:center; text-align:center">
                <div class="stat-value" style="color:${s.color}">${s.value}</div>
                <div class="stat-label">${s.label}</div>
            </div>`).join('');

        const rows = (audit.entries || []).map(e => {
            const c = strengthColor(e.score);
            return `
                <div class="audit-table-row">
                    <span class="audit-website">${esc(e.website)}</span>
                    <span class="audit-user">${esc(e.username)}</span>
                    <div>${strengthBarHTML(e.score)}</div>
                    <span class="audit-strength" style="color:${c}">${strengthName(e.strength)}</span>
                </div>`;
        }).join('');
        $('#audit-table-body').innerHTML = rows || '<div class="entry-empty">No entries to audit</div>';
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER: SETTINGS
    // ═══════════════════════════════════════════════════════════════════
    function renderSettings() {
        if (state.user) {
            $('#settings-email').value = state.user.email;
        }
    }


    // ═══════════════════════════════════════════════════════════════════
    //  VAULT CRUD
    // ═══════════════════════════════════════════════════════════════════
    function openAddModal() {
        state.editingEntryId = null;
        $('#modal-entry-title').textContent = 'Add Password';
        $('#entry-save-btn').textContent = 'Add to Vault';
        $('#entry-website').value = '';
        $('#entry-username').value = '';
        $('#entry-password').value = '';
        $('#entry-notes').value = '';
        show($('#modal-entry'));
    }

    function openEditModal(entryId) {
        const entry = state.entries.find(e => e.entry_id === entryId);
        if (!entry) return;
        state.editingEntryId = entryId;
        $('#modal-entry-title').textContent = 'Edit Entry';
        $('#entry-save-btn').textContent = 'Save Changes';
        $('#entry-website').value = entry.website;
        $('#entry-username').value = entry.username;
        $('#entry-password').value = entry.password;
        $('#entry-notes').value = entry.notes || '';
        show($('#modal-entry'));
    }

    async function saveEntry() {
        const website  = $('#entry-website').value.trim();
        const username = $('#entry-username').value.trim();
        const password = $('#entry-password').value;
        const notes    = $('#entry-notes').value.trim();

        if (!website || !username || !password) {
            toast('Website, username, and password are required', 'error');
            return;
        }

        try {
            if (state.editingEntryId) {
                // UPDATE
                await API.put('/vault/entries/' + state.editingEntryId, { website, username, password, notes });
                toast('Entry updated');
            } else {
                // CREATE
                await API.post('/vault/entries', { website, username, password, notes });
                toast('Password added to vault');
            }
            await loadVaultEntries();
            await loadHealthAudit();
            renderVault($('#vault-search').value);
            hide($('#modal-entry'));
        } catch (err) {
            toast(err.message || 'Failed to save', 'error');
        }
    }

    function openDeleteModal(entryId) {
        const entry = state.entries.find(e => e.entry_id === entryId);
        if (!entry) return;
        state.deleteEntryId = entryId;
        $('#delete-target').textContent = entry.website;
        show($('#modal-delete'));
    }

    async function confirmDelete() {
        if (!state.deleteEntryId) return;
        try {
            await API.del('/vault/entries/' + state.deleteEntryId);
            toast('Entry deleted');
            await loadVaultEntries();
            await loadHealthAudit();
            renderVault($('#vault-search').value);
            hide($('#modal-delete'));
        } catch (err) {
            toast(err.message || 'Failed to delete', 'error');
        }
    }


    // ═══════════════════════════════════════════════════════════════════
    //  SIGN OUT
    // ═══════════════════════════════════════════════════════════════════
    async function signOut() {
        try {
            await API.post('/auth/logout');
        } catch { /* ignore */ }
        window.location.href = '/';
    }

    // clear vault
    async function clearVault() {
        try {
            await API.post('/vault/clear');
            toast('Vault cleared');
            await loadVaultEntries();
            await loadHealthAudit();
            renderVault($('#vault-search').value);
        } catch (err) {
            toast(err.message || 'Failed to clear vault', 'error');
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EVENT BINDINGS
    // ═══════════════════════════════════════════════════════════════════
    function bindEvents() {

        // Sidebar toggle
        $('#sidebar-toggle').addEventListener('click', () => {
            $('#sidebar').classList.toggle('collapsed');
        });

        // Navigation
        $$('.nav-btn[data-page]').forEach(btn => {
            btn.addEventListener('click', () => navigateTo(btn.dataset.page));
        });

        // Sign out
        $('#signout-btn').addEventListener('click', () => show($('#modal-signout')));
        $('#signout-confirm-btn').addEventListener('click', signOut);

        // Modal close buttons
        $$('[data-close]').forEach(btn => {
            btn.addEventListener('click', () => hide($('#' + btn.dataset.close)));
        });
        // Close modals on overlay click
        $$('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) hide(overlay);
            });
        });

        // ─── Vault ───
        $('#vault-add-btn').addEventListener('click', openAddModal);
        $('#entry-save-btn').addEventListener('click', saveEntry);
        $('#delete-confirm-btn').addEventListener('click', confirmDelete);

        $('#vault-search').addEventListener('input', (e) => {
            renderVault(e.target.value);
        });

        // Vault entry actions (delegated)
        $('#vault-list').addEventListener('click', (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            const action = btn.dataset.action;
            const id = btn.dataset.id;

            if (action === 'reveal') {
                if (revealedIds.has(id)) revealedIds.delete(id); else revealedIds.add(id);
                renderVault($('#vault-search').value);
            }
            if (action === 'copy') {
                const entry = state.entries.find(e => e.entry_id === id);
                if (entry) copyToClipboard(entry.password);
            }
            if (action === 'edit')   openEditModal(id);
            if (action === 'delete') openDeleteModal(id);
        });

        // ─── Generator ───
        $$('.mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                generatorMode = btn.dataset.mode;
                $$('.mode-btn').forEach(b => b.classList.toggle('active', b === btn));
                if (generatorMode === 'password') {
                    show($('#gen-password-opts'));
                    hide($('#gen-passphrase-opts'));
                } else {
                    hide($('#gen-password-opts'));
                    show($('#gen-passphrase-opts'));
                }
            });
        });

        $('#gen-length').addEventListener('input', (e) => {
            $('#gen-length-val').textContent = e.target.value;
        });
        $('#gen-words').addEventListener('input', (e) => {
            $('#gen-words-val').textContent = e.target.value;
        });

        $('#gen-go-password').addEventListener('click', generatePassword);
        $('#gen-go-passphrase').addEventListener('click', generatePassphrase);
        $('#gen-regen-btn').addEventListener('click', () => {
            generatorMode === 'password' ? generatePassword() : generatePassphrase();
        });
        $('#gen-copy-btn').addEventListener('click', () => {
            const text = $('#gen-output').textContent;
            if (text && text !== '—') copyToClipboard(text);
        });

        // ─── Analyzer ───
        $('#analyzer-go-btn').addEventListener('click', analyzePassword);
        $('#analyzer-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') analyzePassword();
        });

        // ─── Settings ───
        $('#settings-email-btn').addEventListener('click', () => toast('Email update not yet implemented', 'info'));
        $('#settings-pwd-btn').addEventListener('click', () => {
            const cur     = $('#settings-cur-pwd').value;
            const newPwd  = $('#settings-new-pwd').value;
            const confirm = $('#settings-confirm-pwd').value;
            if (!cur || !newPwd) { toast('Fill in all password fields', 'error'); return; }
            if (newPwd !== confirm) { toast('New passwords do not match', 'error'); return; }
            toast('Password change not yet implemented', 'info');
        });
        $('#settings-delete-btn').addEventListener('click', () => toast('Account deletion not yet implemented', 'info'));
        $('#settings-clear-btn').addEventListener('click', () => show($('#modal-clear')));
        $('#clear-confirm-btn').addEventListener('click', clearVault);
        
    }


    // ═══════════════════════════════════════════════════════════════════
    //  INIT
    // ═══════════════════════════════════════════════════════════════════
    async function init() {
        bindEvents();

        // Load data in parallel
        await loadUser();
        await Promise.all([loadVaultEntries(), loadHealthAudit()]);

        // Initial render
        navigateTo('overview');

        // Pre-generate a password for the generator tab
        clientGeneratePassword({ length: 16 });
    }

    // Boot
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();