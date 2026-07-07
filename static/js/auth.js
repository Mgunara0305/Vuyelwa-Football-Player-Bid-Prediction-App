/* ═══════════════════════════════════════════
   auth.js — VuyelwaDiski
   Multi-step form, password strength,
   real-time validation, show/hide password
   ═══════════════════════════════════════════ */

let currentStep = 0;
const totalSteps = 3;

/* ─── Multi-step Navigation ─── */
function goToStep(n) {
  // Validate current step before moving forward
  if (n > currentStep && !validateStep(currentStep)) return;

  document.getElementById('step-' + currentStep)?.classList.remove('active');
  document.getElementById('step-' + n)?.classList.add('active');

  // Update dots
  for (let i = 0; i < totalSteps; i++) {
    const dot = document.getElementById('dot-' + i);
    if (!dot) continue;
    dot.classList.remove('active', 'done');
    if (i === n) dot.classList.add('active');
    else if (i < n) dot.classList.add('done');
  }
  currentStep = n;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function validateStep(step) {
  if (step === 0) {
    const name = document.getElementById('full_name');
    if (!name || name.value.trim().length < 2) {
      if (name) { name.style.borderColor = 'var(--red-alert)'; name.focus(); }
      return false;
    }
    if (name) name.style.borderColor = '';
  }
  if (step === 1) {
    const username = document.getElementById('username');
    const email    = document.getElementById('email');
    const pwd      = document.getElementById('reg-password');
    const cpwd     = document.getElementById('reg-confirm-password');

    if (!username || username.value.trim().length < 4) {
      if (username) { username.style.borderColor = 'var(--red-alert)'; username.focus(); }
      return false;
    }
    if (!email || !email.value.includes('@')) {
      if (email) { email.style.borderColor = 'var(--red-alert)'; email.focus(); }
      return false;
    }
    if (!pwd || pwd.value.length < 8) {
      if (pwd) { pwd.style.borderColor = 'var(--red-alert)'; pwd.focus(); }
      return false;
    }
    if (!cpwd || cpwd.value !== pwd.value) {
      if (cpwd) { cpwd.style.borderColor = 'var(--red-alert)'; cpwd.focus(); }
      showFeedback('confirm-pw-feedback', false, 'Passwords do not match');
      return false;
    }
    [username, email, pwd, cpwd].forEach(el => { if (el) el.style.borderColor = ''; });
  }
  return true;
}

/* ─── Show/Hide Password ─── */
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
  } else {
    input.type = 'password';
    btn.innerHTML = '<i class="fa-solid fa-eye"></i>';
  }
}

/* ─── Password Strength Meter ─── */
function checkStrength(input) {
  const pwd = input.value;
  const fill  = document.getElementById('strength-fill');
  const label = document.getElementById('strength-label');
  if (!fill || !label) return;

  let score = 0;
  if (pwd.length >= 8)               score++;
  if (/[A-Z]/.test(pwd))            score++;
  if (/[0-9]/.test(pwd))            score++;
  if (/[^A-Za-z0-9]/.test(pwd))    score++;

  const levels = [
    { cls: '',       text: 'Enter a password (min 8 characters)' },
    { cls: 'weak',   text: '⚠️ Weak — try adding uppercase letters' },
    { cls: 'fair',   text: '📊 Fair — add numbers or symbols' },
    { cls: 'good',   text: '👍 Good — almost there!' },
    { cls: 'strong', text: '✅ Strong password!' },
  ];
  const level = pwd.length === 0 ? levels[0] : levels[Math.min(score, 4)];
  fill.className = 'strength-fill ' + level.cls;
  label.textContent = level.text;
  label.style.color = score >= 3 ? 'var(--green)' : score >= 2 ? 'var(--gold)' : 'var(--orange)';
}

/* ─── Real-time Username Check ─── */
let usernameTimer;
function checkUsername(input) {
  clearTimeout(usernameTimer);
  const val = input.value.trim();
  const fb  = document.getElementById('username-feedback');
  if (!fb) return;
  if (val.length < 4) { fb.textContent = ''; return; }

  fb.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking...';
  fb.className = 'field-feedback';

  usernameTimer = setTimeout(function() {
    fetch('/api/check-username?username=' + encodeURIComponent(val))
      .then(r => r.json())
      .then(data => {
        if (data.available) {
          fb.innerHTML = '<i class="fa-solid fa-circle-check"></i> Username available';
          fb.className = 'field-feedback valid';
          input.style.borderColor = 'var(--green)';
        } else {
          fb.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> Username already taken';
          fb.className = 'field-feedback invalid';
          input.style.borderColor = 'var(--red-alert)';
        }
      });
  }, 500);
}

/* ─── Real-time Email Check ─── */
let emailTimer;
function checkEmail(input) {
  clearTimeout(emailTimer);
  const val = input.value.trim();
  const fb  = document.getElementById('email-feedback');
  if (!fb) return;
  if (!val.includes('@')) { fb.textContent = ''; return; }

  fb.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking...';
  fb.className = 'field-feedback';

  emailTimer = setTimeout(function() {
    fetch('/api/check-email?email=' + encodeURIComponent(val))
      .then(r => r.json())
      .then(data => {
        if (data.available) {
          fb.innerHTML = '<i class="fa-solid fa-circle-check"></i> Email available';
          fb.className = 'field-feedback valid';
          input.style.borderColor = 'var(--green)';
        } else {
          fb.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> Email already registered';
          fb.className = 'field-feedback invalid';
          input.style.borderColor = 'var(--red-alert)';
        }
      });
  }, 500);
}

/* ─── Role Selector ─── */
function selectRole(role) {
  document.getElementById('role-fan')?.classList.remove('selected');
  document.getElementById('role-admin')?.classList.remove('selected');
  const selected = document.getElementById('role-' + role);
  if (selected) selected.classList.add('selected');
  const hidden = document.getElementById('role-hidden');
  if (hidden) hidden.value = role;
}

/* ─── Helper ─── */
function showFeedback(id, ok, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'field-feedback ' + (ok ? 'valid' : 'invalid');
}

/* ─── Login form submit animation ─── */
const loginForm = document.getElementById('login-form');
if (loginForm) {
  loginForm.addEventListener('submit', function() {
    const btn = document.getElementById('login-submit-btn');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Signing in...';
    }
  });
}
