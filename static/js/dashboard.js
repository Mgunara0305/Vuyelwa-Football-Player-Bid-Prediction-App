/* ═══════════════════════════════════════════
   dashboard.js — VuyelwaDiski
   Position tabs, AJAX predict, radar chart
   ═══════════════════════════════════════════ */

// Map of position code -> panel id and tab id
const POSITION_MAP = {
  // Goalkeeper
  'GK':  { panel: 'gk',  tab: 'gk'  },
  // Defenders
  'CB':  { panel: 'def', tab: 'def' },
  'LB':  { panel: 'def', tab: 'def' },
  'RB':  { panel: 'def', tab: 'def' },
  'LWB': { panel: 'def', tab: 'def' },
  'RWB': { panel: 'def', tab: 'def' },
  // Midfielders
  'CM':  { panel: 'mid', tab: 'mid' },
  'CAM': { panel: 'mid', tab: 'mid' },
  'CDM': { panel: 'mid', tab: 'mid' },
  'LM':  { panel: 'mid', tab: 'mid' },
  'RM':  { panel: 'mid', tab: 'mid' },
  // Forwards
  'ST':  { panel: 'fwd', tab: 'fwd' },
  'CF':  { panel: 'fwd', tab: 'fwd' },
  'LW':  { panel: 'fwd', tab: 'fwd' },
  'RW':  { panel: 'fwd', tab: 'fwd' },
};

let radarChart = null;

/* ─── Position Change Handler ─── */
function onPositionChange(posValue) {
  if (!posValue) return;
  const mapping = POSITION_MAP[posValue.trim().toUpperCase()];
  if (mapping) {
    showAttrPanel(mapping.panel);
  }
}

/* ─── Show Attribute Panel ─── */
function showAttrPanel(panelId) {
  // Deactivate all panels
  document.querySelectorAll('.attr-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.pos-tab').forEach(t => t.classList.remove('active'));

  // Activate selected
  const panel = document.getElementById('panel-' + panelId);
  const tab   = document.getElementById('tab-' + panelId);
  if (panel) panel.classList.add('active');
  if (tab)   tab.classList.add('active');
}

/* ─── Send Prediction ─── */
function sendPrediction() {
  const form = document.getElementById('predict-form');

  // Validate position is selected
  const posEl = document.getElementById('position');
  if (!posEl.value) {
    posEl.focus();
    posEl.style.borderColor = 'var(--red-alert)';
    setTimeout(() => { posEl.style.borderColor = ''; }, 2000);
    return;
  }

  // Collect all form values (including from hidden selects in non-active panels)
  const fd = new FormData(form);

  // Show loading
  const btn = document.getElementById('predict-btn');
  const loadingEl = document.getElementById('loading-state');
  const resultEl  = document.getElementById('prediction-result');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Predicting...';
  loadingEl.style.display = 'block';
  resultEl.classList.remove('visible');
  resultEl.style.display = 'none';

  fetch('/predict', {
    method: 'POST',
    body: fd
  })
  .then(res => res.json())
  .then(data => {
    loadingEl.style.display = 'none';
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Predict Player Value';

    if (data.error) {
      alert('Prediction error: ' + data.error);
      return;
    }

    // Show result
    document.getElementById('predicted-value').textContent = data.formatted;
    const pos = posEl.value;
    const posLabels = {
      'GK':'Goalkeeper', 'CB':'Centre Back', 'LB':'Left Back', 'RB':'Right Back',
      'LWB':'Left Wing Back', 'RWB':'Right Wing Back',
      'CM':'Central Midfielder', 'CAM':'Attacking Midfielder', 'CDM':'Defensive Midfielder',
      'LM':'Left Midfielder', 'RM':'Right Midfielder',
      'ST':'Striker', 'CF':'Centre Forward', 'LW':'Left Winger', 'RW':'Right Winger'
    };
    document.getElementById('predicted-position-label').textContent =
      'Position: ' + (posLabels[pos] || pos);

    resultEl.style.display = 'block';
    setTimeout(() => resultEl.classList.add('visible'), 10);

    // Draw radar chart
    drawRadar(fd);

    // Scroll to result
    resultEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  })
  .catch(err => {
    loadingEl.style.display = 'none';
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Predict Player Value';
    alert('Network error. Please try again.');
    console.error(err);
  });
}

/* ─── Radar Chart ─── */
function drawRadar(fd) {
  const pace        = parseInt(fd.get('pace') || 0);
  const shooting    = parseInt(fd.get('shooting') || 0);
  const passing     = parseInt(fd.get('passing') || 0);
  const dribbling   = parseInt(fd.get('dribbling') || 0);
  const defending   = parseInt(fd.get('defending') || 0);
  const physicality = parseInt(fd.get('physicality') || 0);

  const ctx = document.getElementById('radarChart').getContext('2d');

  if (radarChart) radarChart.destroy();

  radarChart = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: ['Pace', 'Shooting', 'Passing', 'Dribbling', 'Defending', 'Physicality'],
      datasets: [{
        data: [pace, shooting, passing, dribbling, defending, physicality],
        backgroundColor: 'rgba(0, 230, 118, 0.15)',
        borderColor: '#00E676',
        borderWidth: 2,
        pointBackgroundColor: '#00E676',
        pointBorderColor: '#00E676',
        pointRadius: 4,
        pointHoverRadius: 6,
      }]
    },
    options: {
      responsive: true,
      animation: { duration: 800, easing: 'easeInOutQuart' },
      scales: {
        r: {
          min: 0, max: 99,
          ticks: {
            stepSize: 25,
            color: 'rgba(255,255,255,0.3)',
            font: { size: 10 },
            backdropColor: 'transparent'
          },
          grid:  { color: 'rgba(255,255,255,0.08)' },
          angleLines: { color: 'rgba(255,255,255,0.08)' },
          pointLabels: {
            color: 'rgba(255,255,255,0.7)',
            font: { size: 11, family: "'Outfit', sans-serif", weight: '600' }
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(13,21,38,0.95)',
          titleColor: '#00E676',
          bodyColor: '#F0F4FF',
          borderColor: 'rgba(0,230,118,0.3)',
          borderWidth: 1,
        }
      }
    }
  });
}

/* ─── Refresh Trivia ─── */
function refreshTrivia() {
  fetch('/api/trivia/random')
    .then(r => r.json())
    .then(data => {
      const banner = document.querySelector('.trivia-banner');
      if (banner) {
        banner.querySelector('.t-emoji').textContent = data.emoji;
        banner.querySelector('div > div').textContent = data.fact;
        banner.style.animation = 'none';
        banner.offsetHeight; // reflow
        banner.style.animation = 'fadeInUp 0.3s ease';
      }
    });
}

/* ─── Reset Form ─── */
function resetForm() {
  document.getElementById('predict-form').reset();
  document.getElementById('prediction-result').classList.remove('visible');
  document.getElementById('prediction-result').style.display = 'none';
  showAttrPanel('all');
  if (radarChart) { radarChart.destroy(); radarChart = null; }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ─── Init ─── */
document.addEventListener('DOMContentLoaded', function() {
  // If a position is pre-selected (e.g. after form error), switch panel
  const posEl = document.getElementById('position');
  if (posEl && posEl.value) onPositionChange(posEl.value);
});
