/**
 * PassMetric Auth — Login & Register
 */

// Check if already logged in
(async function checkSession() {
    try {
        await API.get('/auth/me');
        window.location.href = '/dashboard';
    } catch {
        // Not logged in, stay on auth page
    }
})();

// Switch between login/register forms
function switchForm(target) {
    document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
    document.getElementById(target + '-form').classList.add('active');
    // Clear errors
    document.getElementById('login-error').classList.add('hidden');
    document.getElementById('register-error').classList.add('hidden');
}

// Strength meter for registration
function updateStrengthMeter(password) {
    const bar = document.getElementById('strength-bar');
    const label = document.getElementById('strength-label');

    if (!password) {
        bar.style.width = '0';
        label.textContent = '';
        return;
    }

    // Quick client-side estimate (the real analysis happens server-side)
    let score = 0;
    if (password.length >= 8)  score += 15;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/\d/.test(password))    score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;
    const unique = new Set(password).size;
    if (unique / password.length > 0.7) score += 15;

    score = Math.min(100, score);

    bar.style.width = score + '%';
    bar.style.background = strengthColor(score);

    if (score >= 80) label.textContent = 'Very strong';
    else if (score >= 60) label.textContent = 'Strong';
    else if (score >= 40) label.textContent = 'Medium';
    else if (score >= 20) label.textContent = 'Weak';
    else label.textContent = 'Very weak';

    label.style.color = strengthColor(score);
}

// Login handler
async function handleLogin() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    errorEl.classList.add('hidden');

    if (!email || !password) {
        errorEl.textContent = 'Please enter your email and master password.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Unlocking...';
    btn.querySelector('.btn-loader').classList.remove('hidden');

    try {
        await API.post('/auth/login', { email, master_password: password });
        window.location.href = '/dashboard';
    } catch (err) {
        errorEl.textContent = err.message || 'Login failed. Please check your credentials.';
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Unlock vault';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}

// Register handler
async function handleRegister() {
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;
    const errorEl = document.getElementById('register-error');
    const btn = document.getElementById('register-btn');

    errorEl.classList.add('hidden');

    if (!email || !password) {
        errorEl.textContent = 'Please fill in all fields.';
        errorEl.classList.remove('hidden');
        return;
    }

    if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match.';
        errorEl.classList.remove('hidden');
        return;
    }

    if (password.length < 8) {
        errorEl.textContent = 'Master password must be at least 8 characters.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Creating vault...';
    btn.querySelector('.btn-loader').classList.remove('hidden');

    try {
        await API.post('/auth/register', { email, master_password: password });
        window.location.href = '/dashboard';
    } catch (err) {
        const msg = err.data?.analysis
            ? `${err.message}. ${(err.data.analysis.recommendations || []).join(' ')}`
            : err.message;
        errorEl.textContent = msg;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Create account';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}

// Allow Enter key to submit forms
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    if (loginForm.classList.contains('active')) handleLogin();
    else if (registerForm.classList.contains('active')) handleRegister();
});
