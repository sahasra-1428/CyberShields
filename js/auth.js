/**
 * CYBERSHIELD - Client Authentication Handler
 */

document.addEventListener('DOMContentLoaded', () => {
  // If already authenticated and visiting login or signup, redirect appropriately
  if ((window.location.pathname.endsWith('login.html') || window.location.pathname.endsWith('signup.html')) && Auth.isAuthenticated()) {
    const user = Auth.getUser();
    if (user?.role === 'admin') {
      window.location.href = 'admin-dashboard.html';
    } else {
      window.location.href = 'user-dashboard.html';
    }
    return;
  }

  // Password Visibility Toggles
  document.querySelectorAll('.password-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '👁️‍🗨️';
      } else {
        input.type = 'password';
        btn.textContent = '👁️';
      }
    });
  });

  // Setup Login Form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const submitBtn = loginForm.querySelector('button[type="submit"]');

      if (!email || !password) {
        showToast('Please enter both email and password.', 'error');
        return;
      }

      const origText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Authenticating...';

      try {
        const res = await apiFetch('/api/auth/login', {
          method: 'POST',
          body: { email, password }
        });

        Auth.setToken(res.token);
        Auth.setUser(res.user);

        showToast('Login successful! Welcome back.', 'success');

        // Check if redirect query param exists
        const urlParams = new URLSearchParams(window.location.search);
        const redirect = urlParams.get('redirect');

        setTimeout(() => {
          if (res.user.role === 'admin') {
            window.location.href = 'admin-dashboard.html';
          } else if (redirect && !redirect.includes('login') && !redirect.includes('signup')) {
            window.location.href = redirect;
          } else {
            window.location.href = 'user-dashboard.html';
          }
        }, 800);
      } catch (err) {
        showToast(err.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = origText;
      }
    });
  }

  // Setup Password Reset Modal Handling
  const openForgotModalBtn = document.getElementById('open-forgot-modal');
  const closeResetModalBtn = document.getElementById('close-reset-modal');
  const resetModal = document.getElementById('reset-modal');
  const resetForm = document.getElementById('reset-form');

  if (openForgotModalBtn && resetModal) {
    openForgotModalBtn.addEventListener('click', () => {
      const emailVal = document.getElementById('email')?.value || '';
      if (emailVal) {
        document.getElementById('reset-email').value = emailVal;
      }
      resetModal.style.display = 'flex';
    });
  }

  if (closeResetModalBtn && resetModal) {
    closeResetModalBtn.addEventListener('click', () => {
      resetModal.style.display = 'none';
    });
  }

  if (resetForm) {
    resetForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('reset-email').value.trim();
      const newPassword = document.getElementById('reset-new-password').value;
      const confirmPassword = document.getElementById('reset-confirm-password').value;
      const submitBtn = document.getElementById('submit-reset-btn');

      if (!email || !newPassword) {
        showToast('Please provide email and new password.', 'error');
        return;
      }

      if (newPassword !== confirmPassword) {
        showToast('Passwords do not match.', 'error');
        return;
      }

      const origText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Updating...';

      try {
        const res = await apiFetch('/api/auth/reset-password', {
          method: 'POST',
          body: { email, newPassword, confirmPassword }
        });

        showToast(res.message || 'Password updated successfully! Please login.', 'success');
        resetModal.style.display = 'none';
        resetForm.reset();
        document.getElementById('password').value = newPassword;
        document.getElementById('email').value = email;
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = origText;
      }
    });
  }

  // Setup Signup Form & Password Strength Validation
  const signupForm = document.getElementById('signup-form');
  const passwordInput = document.getElementById('signup-password');

  if (passwordInput) {
    passwordInput.addEventListener('input', () => {
      evaluatePasswordStrength(passwordInput.value);
    });
  }

  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('name').value.trim();
      const email = document.getElementById('email').value.trim();
      const phone = document.getElementById('phone')?.value.trim() || '';
      const password = document.getElementById('signup-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
      const submitBtn = signupForm.querySelector('button[type="submit"]');

      if (!name || !email || !password) {
        showToast('Please fill in all required fields.', 'error');
        return;
      }

      if (password !== confirmPassword) {
        showToast('Passwords do not match.', 'error');
        return;
      }

      const strength = evaluatePasswordStrength(password);
      if (!strength.isValid) {
        showToast('Password does not meet the cybersecurity complexity requirements.', 'error');
        return;
      }

      const origText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Sending OTP...';

      try {
        // Step 1: Dispatch 6-digit cryptographic verification code
        const otpRes = await apiFetch('/api/auth/send-otp', {
          method: 'POST',
          body: { email, purpose: 'registration' }
        });

        // Step 2: Open 6-Box OTP Verification Modal
        const otpModal = document.getElementById('signup-otp-modal');
        const emailLabel = document.getElementById('otp-recipient-email');
        const previewCodeEl = document.getElementById('otp-preview-code');
        const countdownEl = document.getElementById('otp-countdown');
        const resendBtn = document.getElementById('btn-resend-otp');
        const verifyBtn = document.getElementById('btn-verify-otp');
        const cancelBtn = document.getElementById('btn-cancel-otp');
        const otpInputs = document.querySelectorAll('#otp-inputs .otp-digit-input');

        if (emailLabel) emailLabel.textContent = email;
        if (previewCodeEl) previewCodeEl.textContent = otpRes?.data?.previewOtp || 'Dispatched';

        // Setup 6-Box Pattern Handler
        setupOtpInputBoxes('otp-inputs');

        // Countdown Timer Handler
        let remainingSeconds = 300; // 5 minutes
        let timerInterval = null;

        const updateTimer = () => {
          const m = String(Math.floor(remainingSeconds / 60)).padStart(2, '0');
          const s = String(remainingSeconds % 60).padStart(2, '0');
          if (countdownEl) countdownEl.textContent = `${m}:${s}`;
          if (remainingSeconds <= 0) {
            clearInterval(timerInterval);
            if (resendBtn) resendBtn.disabled = false;
          } else {
            remainingSeconds--;
          }
        };

        clearInterval(window.__signupOtpTimer);
        updateTimer();
        window.__signupOtpTimer = setInterval(updateTimer, 1000);
        if (resendBtn) resendBtn.disabled = true;

        if (otpModal) otpModal.style.display = 'flex';
        if (otpInputs[0]) otpInputs[0].focus();

        // Resend Handler
        if (resendBtn) {
          resendBtn.onclick = async () => {
            resendBtn.disabled = true;
            try {
              const freshRes = await apiFetch('/api/auth/send-otp', {
                method: 'POST',
                body: { email, purpose: 'registration' }
              });
              showToast('Fresh verification code sent!', 'info');
              if (previewCodeEl) previewCodeEl.textContent = freshRes?.data?.previewOtp || 'Dispatched';
              remainingSeconds = 300;
              clearInterval(window.__signupOtpTimer);
              window.__signupOtpTimer = setInterval(updateTimer, 1000);
            } catch (err) {
              showToast(err.message, 'error');
              resendBtn.disabled = false;
            }
          };
        }

        // Cancel Handler
        if (cancelBtn) {
          cancelBtn.onclick = () => {
            clearInterval(window.__signupOtpTimer);
            if (otpModal) otpModal.style.display = 'none';
            submitBtn.disabled = false;
            submitBtn.innerHTML = origText;
          };
        }

        // Verify & Activate Registration Handler
        if (verifyBtn) {
          verifyBtn.onclick = async () => {
            const enteredOtp = Array.from(otpInputs).map(i => i.value).join('');

            if (enteredOtp.length !== 6 || !/^\d{6}$/.test(enteredOtp)) {
              showToast('Please enter all 6 numeric digits of your verification code.', 'error');
              return;
            }

            const origVerifyText = verifyBtn.innerHTML;
            verifyBtn.disabled = true;
            verifyBtn.innerHTML = 'Verifying...';

            try {
              // Register with verified OTP
              await apiFetch('/api/auth/register', {
                method: 'POST',
                body: { name, email, phone, password, confirmPassword, otp: enteredOtp }
              });

              clearInterval(window.__signupOtpTimer);
              if (otpModal) otpModal.style.display = 'none';

              showToast('Account activated & verified successfully! Redirecting to login...', 'success');
              setTimeout(() => {
                window.location.href = 'login.html';
              }, 1200);
            } catch (err) {
              showToast(err.message, 'error');
              verifyBtn.disabled = false;
              verifyBtn.innerHTML = origVerifyText;
            }
          };
        }
      } catch (err) {
        showToast(err.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = origText;
      }
    });
  }
});

/**
 * Universal 6-Box OTP Pattern Controller
 * - Auto-advances to next input on digit entry
 * - Backspace moves to previous input
 * - Paste distributes 6 digits automatically across boxes
 */
function setupOtpInputBoxes(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const inputs = container.querySelectorAll('.otp-digit-input');

  inputs.forEach((input, idx) => {
    input.value = '';
    input.classList.remove('filled');

    // Handle single digit entry & auto-advance
    input.oninput = (e) => {
      const val = input.value.replace(/[^0-9]/g, '');
      input.value = val ? val[val.length - 1] : '';

      if (input.value) {
        input.classList.add('filled');
        if (idx < inputs.length - 1) {
          inputs[idx + 1].focus();
        }
      } else {
        input.classList.remove('filled');
      }
    };

    // Handle Backspace navigation
    input.onkeydown = (e) => {
      if (e.key === 'Backspace' && !input.value && idx > 0) {
        inputs[idx - 1].focus();
      } else if (e.key === 'ArrowLeft' && idx > 0) {
        inputs[idx - 1].focus();
      } else if (e.key === 'ArrowRight' && idx < inputs.length - 1) {
        inputs[idx + 1].focus();
      }
    };

    // Handle Paste event (distribute up to 6 digits)
    input.onpaste = (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text');
      const digits = pasteData.replace(/[^0-9]/g, '').slice(0, inputs.length);

      digits.split('').forEach((d, dIdx) => {
        if (inputs[dIdx]) {
          inputs[dIdx].value = d;
          inputs[dIdx].classList.add('filled');
        }
      });

      const nextFocus = Math.min(digits.length, inputs.length - 1);
      if (inputs[nextFocus]) inputs[nextFocus].focus();
    };
  });
}

function evaluatePasswordStrength(pwd) {
  const reqLength = pwd.length >= 8;
  const reqUpper = /[A-Z]/.test(pwd);
  const reqLower = /[a-z]/.test(pwd);
  const reqNumber = /\d/.test(pwd);
  const reqSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd);

  const updateReq = (id, valid) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (valid) {
      el.classList.add('valid');
      el.classList.remove('invalid');
      el.innerHTML = '✓ ' + el.getAttribute('data-label');
    } else {
      el.classList.remove('valid');
      el.classList.add('invalid');
      el.innerHTML = '○ ' + el.getAttribute('data-label');
    }
  };

  updateReq('req-len', reqLength);
  updateReq('req-upper', reqUpper);
  updateReq('req-lower', reqLower);
  updateReq('req-num', reqNumber);
  updateReq('req-special', reqSpecial);

  let score = 0;
  if (reqLength) score += 20;
  if (reqUpper) score += 20;
  if (reqLower) score += 20;
  if (reqNumber) score += 20;
  if (reqSpecial) score += 20;

  const barFill = document.getElementById('strength-bar-fill');
  const label = document.getElementById('strength-text');

  if (barFill && label) {
    barFill.style.width = score + '%';
    if (score <= 40) {
      barFill.style.backgroundColor = '#ef4444';
      label.textContent = 'Weak';
      label.style.color = '#ef4444';
    } else if (score <= 80) {
      barFill.style.backgroundColor = '#f59e0b';
      label.textContent = 'Moderate';
      label.style.color = '#f59e0b';
    } else {
      barFill.style.backgroundColor = '#10b981';
      label.textContent = 'Strong (Cyber-Ready)';
      label.style.color = '#10b981';
    }
  }

  return {
    score,
    isValid: reqLength && reqUpper && reqLower && reqNumber && reqSpecial
  };
}
