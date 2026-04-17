
const API_BASE = '/api';
let csrfToken = null;

// Fetch CSRF token on page load
async function fetchCsrfToken() {
    try {
        const res = await fetch('/api/csrf-token', { credentials: 'include' });
        const data = await res.json();
        csrfToken = data.csrf_token;
    } catch { /* ignore */ }
}

async function api(path, options = {}) {
    if (!csrfToken) await fetchCsrfToken(); // Ensure we have a CSRF token before making requests
    const url = API_BASE + path;
    const config = {
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        credentials: 'include',
        ...options,
    };

    let res;
    try {
        res = await fetch(url, config);
        // If CSRF token is expired, refresh it and retry once
        if (res.status === 400) {
            const body = await res.clone().json();
            if (body.error && body.error.includes('CSRF')) {
                await fetchCsrfToken();
                config.headers['X-CSRFToken'] = csrfToken;
                const retry = await fetch(url, config);
                return retry.json();
            }
        }
    } catch (netErr) {
        // Network-level failure (server down, CORS, etc.)
        const err = new Error('Network error — could not reach server.');
        err.status = 0;
        err.data = {};
        throw err;
    }

    // Try to parse the body as JSON. If the server returned HTML (e.g. a
    // Flask debug error page), fall back to a plain-text error.
    let data;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        try {
            data = await res.json();
        } catch {
            data = {};
        }
    } else {
        data = { error: `Server returned a non-JSON response (${res.status}).` };
    }

    if (!res.ok) {
        const err = new Error(data.error || `Request failed (${res.status})`);
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

// Convenience methods
const API = {
    get:  (path)       => api(path, { method: 'GET' }),
    post: (path, body) => api(path, { method: 'POST', body: JSON.stringify(body) }),
    put:  (path, body) => api(path, { method: 'PUT',  body: JSON.stringify(body) }),
    del:  (path)       => api(path, { method: 'DELETE' }),
};

// Session-expired redirect handled here so every caller doesn't have to
const _origApi = api;
window.addEventListener('unhandledrejection', (ev) => {
    const err = ev.reason;
    if (err && err.status === 401 && !String(err.message || '').includes('/auth/')) {
        window.location.href = '/';
    }
});

// Shared helpers

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.style.opacity = isPassword ? '1' : '0.5';
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard');
    } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied to clipboard');
    }
}

function showToast(msg) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.style.cssText = `
            position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
            background: #2ecc71; color: #fff; padding: 10px 24px;
            border-radius: 6px; font-size: 14px; font-weight: 500;
            z-index: 300; opacity: 0; transition: opacity 0.3s;
            pointer-events: none;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.opacity = '1';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 2000);
}

function strengthColor(score) {
    if (score >= 80) return 'var(--str-very-strong)';
    if (score >= 60) return 'var(--str-strong)';
    if (score >= 40) return 'var(--str-medium)';
    if (score >= 20) return 'var(--str-weak)';
    return 'var(--str-very-weak)';
}

function strengthName(str) {
    return (str || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
