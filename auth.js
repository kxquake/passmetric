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
        if (err.status === 423) {
            // Account locked
            errorEl.textContent = err.data?.error || 'Account temporarily locked.';
            btn.disabled = true;
            // Re-enable button after retry period
            const retryAfter = (err.data?.retry_after_seconds || 60) * 1000;
            setTimeout(() => { btn.disabled = false; }, retryAfter);
        } else if (err.status === 429) {
            errorEl.textContent = 'Too many requests. Please slow down.';
        } else {
            let msg = err.data?.error || 'Login failed.';
            if (err.data?.attempts_remaining !== undefined) {
                msg += ` (${err.data.attempts_remaining} attempt${err.data.attempts_remaining !== 1 ? 's' : ''} remaining)`;
            }
            errorEl.textContent = msg;
        }
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Unlock vault';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}

// Register handler
async function handleRegister(confirmWeak = false) {
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;
    const checkBreaches = document.getElementById('register-check-breaches')?.checked ?? true;
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
        await API.post('/auth/register', {
            email,
            master_password: password,
            check_breaches: checkBreaches,
            confirm_weak: confirmWeak,
        });
        window.location.href = '/dashboard';
    } catch (err) {
        // ── Bitwarden-style modal: server says password is weak/breached ──
        if (err.data?.requires_confirmation) {
            showWeakPasswordModal(err.data);
            return;
        }

        // Any other error — show the message (fall back if response wasn't JSON)
        const msg = err.data?.error
            ?? err.message
            ?? 'Something went wrong. Please try again.';
        errorEl.textContent = msg;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Create account';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}

// ── Bitwarden-style "Weak and Exposed Master Password" modal ──
function showWeakPasswordModal(data) {
    const modal = document.getElementById('weak-pw-modal');
    const body = document.getElementById('weak-pw-body');
    const title = document.getElementById('weak-pw-title');

    let titleText = 'Weak Master Password';
    let bodyText = 'Weak passwords can be easily guessed by attackers. ';

    if (data.is_breached && data.is_weak) {
        titleText = 'Weak and Exposed Master Password';
        bodyText = 'Weak password identified and found in a data breach. '
                 + 'Use a strong and unique password to protect your account. '
                 + 'Are you sure you want to use this password?';
    } else if (data.is_breached) {
        titleText = 'Exposed Master Password';
        bodyText = 'This password has been found in a known data breach and '
                 + 'is easy for attackers to guess. Are you sure you want to '
                 + 'use this password?';
    } else {
        bodyText += 'Use a strong and unique password to protect your account. '
                  + 'Are you sure you want to use this password?';
    }

    title.textContent = titleText;
    body.textContent = bodyText;
    modal.classList.remove('hidden');

    // Rebind buttons each time so stale handlers don't accumulate
    const yesBtn = document.getElementById('weak-pw-yes');
    const noBtn = document.getElementById('weak-pw-no');
    const newYes = yesBtn.cloneNode(true);
    const newNo = noBtn.cloneNode(true);
    yesBtn.replaceWith(newYes);
    noBtn.replaceWith(newNo);

    newYes.addEventListener('click', () => {
        modal.classList.add('hidden');
        handleRegister(true);   // ← retry with confirm_weak = true
    });
    newNo.addEventListener('click', () => {
        modal.classList.add('hidden');
        document.getElementById('register-password').focus();
    });
}

// Allow Enter key to submit forms
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    if (loginForm.classList.contains('active')) handleLogin();
    else if (registerForm.classList.contains('active')) handleRegister();
});
