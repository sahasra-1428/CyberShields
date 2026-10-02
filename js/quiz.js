/**
 * CYBERSHIELD - Interactive Cyber Crime Readiness Quiz Engine
 */

document.addEventListener('DOMContentLoaded', async () => {
  let questions = [];
  let currentIndex = 0;
  let selectedOption = null;
  const userAnswers = {};

  // UI Elements
  const playView = document.getElementById('quiz-play-view');
  const resultsView = document.getElementById('quiz-results-view');
  const categoryTag = document.getElementById('quiz-category-tag');
  const stepCounter = document.getElementById('quiz-step-counter');
  const progressBar = document.getElementById('quiz-progress-bar');
  const scenarioText = document.getElementById('quiz-scenario-text');
  const optionsContainer = document.getElementById('quiz-options-container');
  const explanationBox = document.getElementById('quiz-explanation-box');
  const feedbackTitle = document.getElementById('quiz-feedback-title');
  const feedbackText = document.getElementById('quiz-feedback-text');
  const submitAnswerBtn = document.getElementById('btn-submit-answer');
  const nextQuestionBtn = document.getElementById('btn-next-question');
  const retakeBtn = document.getElementById('btn-retake-quiz');

  // Load questions
  await initQuiz();

  async function initQuiz() {
    try {
      const res = await AwarenessAPI.getQuizQuestions();
      if (!res.success) throw new Error(res.error?.message || 'Failed to load quiz.');

      questions = res.questions || [];
      currentIndex = 0;
      selectedOption = null;
      for (const k in userAnswers) delete userAnswers[k];

      if (playView) playView.style.display = 'block';
      if (resultsView) resultsView.style.display = 'none';

      renderCurrentQuestion();
    } catch (err) {
      showToast(err.message, 'error');
      if (scenarioText) {
        scenarioText.textContent = 'Error connecting to CyberShield Quiz repository: ' + err.message;
      }
    }
  }

  function renderCurrentQuestion() {
    if (!questions.length || currentIndex >= questions.length) return;

    const q = questions[currentIndex];
    selectedOption = null;

    // Reset buttons and feedback
    submitAnswerBtn.style.display = 'inline-block';
    submitAnswerBtn.disabled = true;
    nextQuestionBtn.style.display = 'none';
    explanationBox.style.display = 'none';
    explanationBox.className = 'explanation-card';

    // Update progress
    const pct = Math.round(((currentIndex + 1) / questions.length) * 100);
    if (progressBar) progressBar.style.width = pct + '%';
    if (stepCounter) stepCounter.textContent = `Question ${currentIndex + 1} of ${questions.length}`;
    if (categoryTag) categoryTag.textContent = q.category || 'Threat Scenario';
    if (scenarioText) scenarioText.textContent = q.scenario;

    // Render options
    const letters = ['A', 'B', 'C', 'D'];
    optionsContainer.innerHTML = q.options.map((opt, idx) => `
      <div class="quiz-option-card" data-idx="${idx}">
        <div class="option-letter">${letters[idx]}</div>
        <div class="option-text">${escapeHtml(opt)}</div>
      </div>
    `).join('');

    // Attach click events
    optionsContainer.querySelectorAll('.quiz-option-card').forEach(card => {
      card.addEventListener('click', () => {
        if (card.classList.contains('locked')) return;

        optionsContainer.querySelectorAll('.quiz-option-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedOption = Number(card.getAttribute('data-idx'));
        submitAnswerBtn.disabled = false;
      });
    });
  }

  // Submit Answer for Current Question
  submitAnswerBtn.addEventListener('click', async () => {
    if (selectedOption === null) return;

    const q = questions[currentIndex];
    userAnswers[q.id] = selectedOption;

    // Lock options
    const allCards = optionsContainer.querySelectorAll('.quiz-option-card');
    allCards.forEach(c => c.classList.add('locked'));

    submitAnswerBtn.disabled = true;
    submitAnswerBtn.innerHTML = 'Verifying...';

    try {
      // Send intermediate single-question answer verification
      const res = await AwarenessAPI.submitQuiz({ [q.id]: selectedOption });
      const itemReview = res?.results?.review?.find(r => r.id === q.id) || res?.results?.review?.[0];

      submitAnswerBtn.style.display = 'none';
      submitAnswerBtn.innerHTML = 'Confirm Choice';
      nextQuestionBtn.style.display = 'inline-block';

      if (currentIndex === questions.length - 1) {
        nextQuestionBtn.innerHTML = 'View Threat Readiness Report →';
      } else {
        nextQuestionBtn.innerHTML = 'Continue to Next Scenario →';
      }

      if (itemReview) {
        if (itemReview.isCorrect) {
          allCards[selectedOption]?.classList.add('correct');
          explanationBox.className = 'explanation-card correct';
          feedbackTitle.innerHTML = '✓ Defensive Choice: Correct!';
          feedbackText.textContent = itemReview.explanation;
        } else {
          // Highlight user's incorrect option in red
          allCards[selectedOption]?.classList.add('incorrect');

          // Highlight the actual correct option in green
          if (itemReview.correctIndex !== undefined && allCards[itemReview.correctIndex]) {
            allCards[itemReview.correctIndex].classList.add('correct');
          }

          explanationBox.className = 'explanation-card incorrect';
          feedbackTitle.innerHTML = '✕ Vulnerable Choice: High Risk Trap!';
          feedbackText.innerHTML = `
            <div style="margin-bottom:8px;">
              <strong style="color:#10b981;">Correct Action:</strong> ${escapeHtml(itemReview.correctOption)}
            </div>
            <div>
              <strong style="color:#f87171;">Threat Analysis:</strong> ${escapeHtml(itemReview.explanation)}
            </div>
          `;
        }
        explanationBox.style.display = 'block';
      }
    } catch (err) {
      showToast(err.message, 'error');
      submitAnswerBtn.disabled = false;
      submitAnswerBtn.innerHTML = 'Confirm Choice';
    }
  });

  // Next Question or Final Results
  nextQuestionBtn.addEventListener('click', async () => {
    if (currentIndex < questions.length - 1) {
      currentIndex++;
      renderCurrentQuestion();
    } else {
      // Submit complete quiz
      await finishQuiz();
    }
  });

  async function finishQuiz() {
    playView.style.display = 'none';
    resultsView.style.display = 'block';

    const scoreNum = document.getElementById('res-score-num');
    const badgeTitle = document.getElementById('res-badge-title');
    const summaryText = document.getElementById('res-summary-text');
    const reviewList = document.getElementById('quiz-review-list');

    try {
      const res = await AwarenessAPI.submitQuiz(userAnswers);
      if (!res.success) throw new Error(res.error?.message);

      const r = res.results;
      if (scoreNum) scoreNum.textContent = `${r.score}`;
      if (badgeTitle) badgeTitle.textContent = r.badge;

      if (summaryText) {
        summaryText.textContent = `You scored ${r.score} out of ${r.total} (${r.percentage}%). Review your detailed scenario triage below:`;
      }

      // Render Question Breakdown List
      if (reviewList && r.review) {
        reviewList.innerHTML = r.review.map((item, idx) => {
          const statusBadge = item.isCorrect
            ? `<span class="badge-risk low-risk" style="font-size:0.75rem;">✓ Defended</span>`
            : `<span class="badge-risk malicious" style="font-size:0.75rem;">✕ Exploited</span>`;

          const borderCol = item.isCorrect ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)';

          return `
            <div style="background:rgba(15,23,42,0.6); border:1px solid ${borderCol}; border-radius:var(--radius-md); padding:16px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-size:0.75rem; text-transform:uppercase; color:var(--cyan); font-weight:700;">Scenario #${idx + 1}: ${escapeHtml(item.category)}</span>
                ${statusBadge}
              </div>
              <div style="font-weight:600; color:#fff; font-size:0.95rem; margin-bottom:10px;">${escapeHtml(item.scenario)}</div>
              
              <div style="font-size:0.85rem; margin-bottom:6px;">
                <span style="color:var(--text-muted);">Your Response:</span> 
                <span style="color:${item.isCorrect ? '#10b981' : '#f87171'}; font-weight:600;">${escapeHtml(item.selectedOption)}</span>
              </div>

              ${!item.isCorrect ? `
                <div style="font-size:0.85rem; margin-bottom:8px;">
                  <span style="color:var(--text-muted);">Defensive Action:</span> 
                  <span style="color:#10b981; font-weight:600;">${escapeHtml(item.correctOption)}</span>
                </div>
              ` : ''}

              <div style="font-size:0.82rem; color:#cbd5e1; background:rgba(0,0,0,0.3); padding:10px 12px; border-radius:4px; margin-top:8px;">
                <strong style="color:var(--cyan);">Cyber Defense Rule:</strong> ${escapeHtml(item.explanation)}
              </div>
            </div>
          `;
        }).join('');
      }

      showToast('Cyber Crime Assessment complete! Score recorded.', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  // Retake button
  if (retakeBtn) {
    retakeBtn.addEventListener('click', () => {
      initQuiz();
    });
  }
});
