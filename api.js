
const API_BASE = '/api';

async function api(path, options = {}) {
    const url = API_BASE + path;
    const config = {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        ...options,
    };

    try {
        const res = await fetch(url, config);
        const data = await res.json();

        if (!res.ok) {
            const err = new Error(data.error || `Request failed (${res.status})`);
            err.status = res.status;
            err.data = data;
            throw err;
        }
        return data;
    } catch (err) {
        if (err.status === 401 && !path.includes('/auth/')) {
            // Session expired — redirect to login
            window.location.href = '/';
        }
        throw err;
    }
}

// Convenience methods
const API = {
    get:  (path)       => api(path, { method: 'GET' }),
    post: (path, body) => api(path, { method: 'POST', body: JSON.stringify(body) }),
    put:  (path, body) => api(path, { method: 'PUT',  body: JSON.stringify(body) }),
    del:  (path)       => api(path, { method: 'DELETE' }),
};

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
