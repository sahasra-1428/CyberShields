/**
 * CYBERSHIELD - QR Scanner Frontend Controller (Camera + Image File Upload)
 */

document.addEventListener('DOMContentLoaded', () => {
  const uploadModeBtn = document.getElementById('btn-mode-upload');
  const cameraModeBtn = document.getElementById('btn-mode-camera');
  const uploadSection = document.getElementById('qr-upload-section');
  const cameraSection = document.getElementById('qr-camera-section');
  const fileInput = document.getElementById('qr-file-input');
  const dropzone = document.getElementById('qr-dropzone');
  const manualForm = document.getElementById('qr-manual-form');
  const manualInput = document.getElementById('qr-manual-input');

  const video = document.getElementById('qr-video');
  const startCameraBtn = document.getElementById('btn-start-camera');
  const stopCameraBtn = document.getElementById('btn-stop-camera');

  const loadingBox = document.getElementById('scanner-loading');
  const loadingStep = document.getElementById('loading-step-text');
  const resultCard = document.getElementById('scanner-result');

  let videoStream = null;
  let scanningActive = false;

  // Toggle Tabs
  if (uploadModeBtn && cameraModeBtn) {
    uploadModeBtn.addEventListener('click', () => {
      uploadModeBtn.classList.add('active');
      cameraModeBtn.classList.remove('active');
      uploadSection.style.display = 'block';
      cameraSection.style.display = 'none';
      stopCamera();
    });

    cameraModeBtn.addEventListener('click', () => {
      cameraModeBtn.classList.add('active');
      uploadModeBtn.classList.remove('active');
      cameraSection.style.display = 'block';
      uploadSection.style.display = 'none';
    });
  }

  // File Upload & Drag-and-Drop
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        handleQrFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleQrFile(e.target.files[0]);
      }
    });
  }

  // Manual fallback submission
  if (manualForm) {
    manualForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const content = manualInput.value.trim();
      if (content) {
        processQrPayload(content);
      } else {
        showToast('Please provide decoded QR content or upload an image.', 'error');
      }
    });
  }

  // Camera Management
  if (startCameraBtn) {
    startCameraBtn.addEventListener('click', async () => {
      try {
        videoStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' }
        });
        video.srcObject = videoStream;
        video.setAttribute('playsinline', true);
        video.play();
        document.getElementById('camera-preview-box').style.display = 'block';
        startCameraBtn.style.display = 'none';
        stopCameraBtn.style.display = 'inline-flex';
        scanningActive = true;
        requestAnimationFrame(tickScan);
      } catch (err) {
        showToast('Camera access denied or unavailable: ' + err.message, 'error');
      }
    });
  }

  if (stopCameraBtn) {
    stopCameraBtn.addEventListener('click', stopCamera);
  }

  function stopCamera() {
    scanningActive = false;
    if (videoStream) {
      videoStream.getTracks().forEach(track => track.stop());
      videoStream = null;
    }
    const preview = document.getElementById('camera-preview-box');
    if (preview) preview.style.display = 'none';
    if (startCameraBtn) startCameraBtn.style.display = 'inline-flex';
    if (stopCameraBtn) stopCameraBtn.style.display = 'none';
  }

  function tickScan() {
    if (!scanningActive) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (window.jsQR) {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert'
        });
        if (code && code.data) {
          stopCamera();
          processQrPayload(code.data);
          return;
        }
      }
    }
    requestAnimationFrame(tickScan);
  }

  function handleQrFile(file) {
    if (!file.type.startsWith('image/')) {
      showToast('Please upload an image file (PNG, JPG, WEBP).', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        if (window.jsQR) {
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code && code.data) {
            processQrPayload(code.data);
          } else {
            showToast('No readable QR code found in this image. Try entering the destination manually.', 'warning');
            manualInput.focus();
          }
        } else {
          // If jsQR not loaded yet, fallback to manual input populate
          showToast('Image uploaded. Please verify the decoded QR content.', 'info');
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  async function processQrPayload(content) {
    resultCard.style.display = 'none';
    loadingBox.style.display = 'block';

    const steps = [
      'Decoding QR matrix payload...',
      'Determining target protocol (UPI, Web URL, Telephony, or Text)...',
      'Checking for quishing and deceptive redirection tactics...',
      'Synthesizing central risk advisory...'
    ];

    let stepIdx = 0;
    loadingStep.textContent = steps[0];
    const stepInterval = setInterval(() => {
      stepIdx = (stepIdx + 1) % steps.length;
      loadingStep.textContent = steps[stepIdx];
    }, 600);

    try {
      const res = await ScannersAPI.scanQr(content);
      clearInterval(stepInterval);
      loadingBox.style.display = 'none';

      if (!res.success) {
        throw new Error(res.error?.message || 'QR analysis failed.');
      }

      renderScanResult(res.analysis, content);
      showToast('QR destination analyzed.', 'success');
    } catch (err) {
      clearInterval(stepInterval);
      loadingBox.style.display = 'none';
      showToast(err.message, 'error');
    }
  }

  // Sample QR payload presets
  document.querySelectorAll('.sample-qr-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const payload = btn.getAttribute('data-qr');
      manualInput.value = payload;
      processQrPayload(payload);
    });
  });
});

function renderScanResult(analysis, originalInput) {
  const card = document.getElementById('scanner-result');
  if (!card) return;

  const colorMap = {
    'LOW RISK': '#10b981',
    'SUSPICIOUS': '#f59e0b',
    'HIGH RISK': '#f97316',
    'MALICIOUS': '#ef4444',
    'INVALID': '#64748b',
    'UNKNOWN / UNABLE TO VERIFY': '#818cf8'
  };
  const themeColor = colorMap[analysis.riskLevel] || '#818cf8';

  const riskClass = getRiskCssClass(analysis.riskLevel);
  const riskTagEl = document.getElementById('result-risk-tag');
  const scoreNumEl = document.getElementById('result-score-num');
  const scoreBarEl = document.getElementById('result-score-bar');

  if (riskTagEl) {
    riskTagEl.className = `risk-level-tag badge-risk ${riskClass}`;
    riskTagEl.textContent = analysis.riskLevel;
  }
  if (scoreNumEl) {
    scoreNumEl.textContent = analysis.riskScore;
    scoreNumEl.style.color = themeColor;
  }
  if (scoreBarEl) {
    scoreBarEl.style.width = analysis.riskScore + '%';
    scoreBarEl.style.backgroundColor = themeColor;
  }

  const explanationEl = document.getElementById('result-explanation');
  if (explanationEl) {
    explanationEl.textContent = analysis.explanation;
  }

  const indicatorsListEl = document.getElementById('result-indicators-list');
  if (indicatorsListEl) {
    indicatorsListEl.innerHTML = (analysis.indicators || []).map(ind => {
      const icon = ind.type === 'alert' ? '⚠' : (ind.type === 'warning' ? '⚠' : (ind.type === 'success' ? '✓' : 'ℹ'));
      return `
        <div class="indicator-item ${ind.type}">
          <span class="indicator-icon">${icon}</span>
          <span>${escapeHtml(ind.text)}</span>
        </div>
      `;
    }).join('');
  }

  const recListEl = document.getElementById('result-recommendations-list');
  if (recListEl) {
    recListEl.innerHTML = (analysis.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
  }

  // Configure Cyber Agent Escalation Button
  const escalateBtn = document.getElementById('btn-escalate-cyber-agent');
  if (escalateBtn) {
    const urgency = ['HIGH RISK', 'MALICIOUS'].includes(analysis.riskLevel) ? 'CRITICAL' : 'HIGH';
    const evidenceSummary = `QR Destination: ${originalInput}. Threat Score: ${analysis.riskScore}/100. Severity: ${analysis.riskLevel}. Indicators: ${(analysis.indicators || []).map(i => i.text).join('; ')}`;
    escalateBtn.href = `report.html?category=other&target=${encodeURIComponent(originalInput)}&urgency=${urgency}&evidence=${encodeURIComponent(evidenceSummary)}`;
  }

  card.style.display = 'block';
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function getRiskCssClass(riskLevel) {
  switch (riskLevel) {
    case 'LOW RISK': return 'low-risk';
    case 'SUSPICIOUS': return 'suspicious';
    case 'HIGH RISK': return 'high-risk';
    case 'MALICIOUS': return 'malicious';
    case 'INVALID': return 'invalid';
    default: return 'unknown';
  }
}
