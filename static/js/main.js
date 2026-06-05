/* =============================================================================
   static/js/main.js  — Cyber Forensic Intelligence System
   ============================================================================= */

// ---------------------------------------------------------------------------
// CSRF helper — reads token from meta tag set by Jinja
// ---------------------------------------------------------------------------
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

// ---------------------------------------------------------------------------
// AI Chat (Forensic Investigator)
// ---------------------------------------------------------------------------
async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg   = input.value.trim();
  if (!msg) return;
  input.value = '';

  const box = document.getElementById('chatMsgs');
  appendMsg(box, 'user', msg);

  const aiDiv = appendMsg(box, 'ai',
    '<div class="ai-label">&#129302; AI ANALYST</div>' +
    '<span style="color:var(--muted)">Analysing evidence database&#8230;</span>');
  box.scrollTop = box.scrollHeight;

  try {
    const res  = await fetch('/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({ message: msg })
    });
    const data = await res.json();
    aiDiv.innerHTML = '<div class="ai-label">&#129302; AI ANALYST</div>' +
                      (data.reply || 'No response.');
  } catch(e) {
    aiDiv.innerHTML = '<div class="ai-label">&#129302; AI ANALYST</div>' +
      '<span style="color:var(--danger)">Connection error.</span>';
  }
  box.scrollTop = box.scrollHeight;
}

function appendMsg(container, type, html) {
  const d = document.createElement('div');
  d.className = 'chat-msg ' + type;
  d.innerHTML = html;
  container.appendChild(d);
  return d;
}

// ---------------------------------------------------------------------------
// Sample-question buttons (Chat page)
// ---------------------------------------------------------------------------
function initSampleQuestions(questions) {
  const div = document.getElementById('sqDiv');
  if (!div) return;
  questions.forEach(q => {
    const btn = document.createElement('button');
    btn.className = 'btn btn-ghost';
    btn.style.cssText = 'width:100%;justify-content:flex-start;font-size:11px;text-align:left;padding:7px 11px';
    btn.textContent = q;
    btn.onclick = () => {
      document.getElementById('chatInput').value = q;
      sendChat();
    };
    div.appendChild(btn);
  });
}

// ---------------------------------------------------------------------------
// File input display name
// ---------------------------------------------------------------------------
function bindFileInput(inputId, labelId) {
  const inp = document.getElementById(inputId);
  const lbl = document.getElementById(labelId);
  if (inp && lbl) {
    inp.addEventListener('change', () => {
      lbl.textContent = inp.files[0] ? inp.files[0].name : '';
    });
  }
}

// ---------------------------------------------------------------------------
// CNN Confusion Matrix — canvas renderer
// ---------------------------------------------------------------------------
function renderConfusionMatrix(canvasId, classes, matrix, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx   = canvas.getContext('2d');
  const n     = classes.length;
  const cell  = options.cellSize || 80;
  const off   = options.offset  || 110;
  const total = off + n * cell;

  canvas.width  = total + 10;
  canvas.height = total + 10;

  ctx.fillStyle = '#041525';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Axis labels
  ctx.fillStyle = '#4a7090';
  ctx.font = 'bold 9px Share Tech Mono, monospace';
  ctx.save();
  ctx.translate(14, off + (n * cell) / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = 'center';
  ctx.fillText('ACTUAL', 0, 0);
  ctx.restore();

  ctx.textAlign = 'center';
  ctx.fillText('PREDICTED', off + (n * cell) / 2, 14);

  // Class labels
  ctx.font = '9px Share Tech Mono, monospace';
  ctx.fillStyle = '#c8dff0';
  classes.forEach((cls, i) => {
    // Top (predicted)
    ctx.textAlign = 'center';
    ctx.save();
    ctx.translate(off + i * cell + cell / 2, off - 8);
    ctx.rotate(-Math.PI / 4);
    ctx.textAlign = 'right';
    ctx.fillText(cls, 0, 0);
    ctx.restore();
    // Left (actual)
    ctx.textAlign = 'right';
    ctx.fillText(cls, off - 6, off + i * cell + cell / 2 + 4);
  });

  // Cells
  const maxVal = Math.max(...matrix.flat(), 1);
  matrix.forEach((row, ti) => {
    row.forEach((val, pi) => {
      const x = off + pi * cell;
      const y = off + ti * cell;
      const intensity = val / maxVal;
      const isDiag = ti === pi;

      if (isDiag) {
        ctx.fillStyle = `rgba(0,255,136,${0.15 + intensity * 0.5})`;
      } else if (val > 0) {
        ctx.fillStyle = `rgba(255,60,60,${0.1 + intensity * 0.4})`;
      } else {
        ctx.fillStyle = 'rgba(255,255,255,0.03)';
      }
      ctx.fillRect(x + 1, y + 1, cell - 2, cell - 2);

      // Border
      ctx.strokeStyle = isDiag ? 'rgba(0,255,136,0.4)' : 'rgba(0,255,231,0.1)';
      ctx.lineWidth = 1;
      ctx.strokeRect(x + 1, y + 1, cell - 2, cell - 2);

      // Value
      ctx.fillStyle = isDiag ? '#00ff88' : (val > 0 ? '#ff3c3c' : '#4a7090');
      ctx.font = `bold ${val > 9 ? 13 : 15}px Share Tech Mono, monospace`;
      ctx.textAlign = 'center';
      ctx.fillText(val, x + cell / 2, y + cell / 2 + 5);
    });
  });
}

// ---------------------------------------------------------------------------
// Accuracy graph — mini line chart on canvas
// ---------------------------------------------------------------------------
function renderAccuracyGraph(canvasId, history, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !history.length) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = { t: 20, r: 20, b: 30, l: 50 };

  ctx.fillStyle = '#041525';
  ctx.fillRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = 'rgba(0,255,231,0.06)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 5; i++) {
    const y = pad.t + (H - pad.t - pad.b) * i / 5;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
    ctx.fillStyle = '#4a7090';
    ctx.font = '8px Share Tech Mono, monospace';
    ctx.textAlign = 'right';
    ctx.fillText((100 - i * 20).toFixed(0) + '%', pad.l - 4, y + 3);
  }

  if (history.length < 2) return;

  // Line
  const xScale = (W - pad.l - pad.r) / (history.length - 1);
  const yScale = (H - pad.t - pad.b) / 100;

  ctx.strokeStyle = '#00ffe7';
  ctx.lineWidth = 2;
  ctx.shadowColor = '#00ffe7';
  ctx.shadowBlur = 6;
  ctx.beginPath();
  history.forEach((v, i) => {
    const x = pad.l + i * xScale;
    const y = pad.t + (H - pad.t - pad.b) - v * yScale;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Fill area
  ctx.fillStyle = 'rgba(0,255,231,0.05)';
  ctx.lineTo(pad.l + (history.length - 1) * xScale, H - pad.b);
  ctx.lineTo(pad.l, H - pad.b);
  ctx.closePath();
  ctx.fill();

  // Final value label
  const lastV = history[history.length - 1];
  const lx = pad.l + (history.length - 1) * xScale;
  const ly = pad.t + (H - pad.t - pad.b) - lastV * yScale;
  ctx.fillStyle = '#00ffe7';
  ctx.font = 'bold 10px Share Tech Mono, monospace';
  ctx.textAlign = 'right';
  ctx.fillText(lastV.toFixed(1) + '%', lx - 4, ly - 6);

  // X-axis label
  ctx.fillStyle = '#4a7090';
  ctx.textAlign = 'center';
  ctx.font = '8px Share Tech Mono, monospace';
  ctx.fillText('SAMPLES →', W / 2, H - 4);
}

// ---------------------------------------------------------------------------
// Precision / Recall bar chart
// ---------------------------------------------------------------------------
function renderPRChart(canvasId, metrics, classes) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const groupW = W / classes.length;
  const barW   = groupW * 0.28;
  const padB   = 50, padT = 20;

  ctx.fillStyle = '#041525';
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = 'rgba(0,255,231,0.06)';
  ctx.lineWidth = 1;
  [0, 25, 50, 75, 100].forEach(pct => {
    const y = padT + (H - padT - padB) * (1 - pct / 100);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    ctx.fillStyle = '#4a7090';
    ctx.font = '8px Share Tech Mono, monospace';
    ctx.textAlign = 'right';
    ctx.fillText(pct + '%', 36, y + 3);
  });

  classes.forEach((cls, i) => {
    const m  = metrics[cls] || { precision: 0, recall: 0, f1: 0 };
    const cx = 40 + i * groupW + groupW / 2;

    // Precision bar (cyan)
    const px = cx - barW - 2;
    const ph = (m.precision / 100) * (H - padT - padB);
    ctx.fillStyle = 'rgba(0,255,231,0.7)';
    ctx.fillRect(px, H - padB - ph, barW, ph);

    // Recall bar (blue)
    const rx = cx + 2;
    const rh = (m.recall / 100) * (H - padT - padB);
    ctx.fillStyle = 'rgba(0,136,255,0.7)';
    ctx.fillRect(rx, H - padB - rh, barW, rh);

    // Class label
    ctx.fillStyle = '#c8dff0';
    ctx.font = '8px Share Tech Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText(cls.replace(' ', '\n'), cx, H - padB + 14);
    ctx.fillText(cls, cx, H - padB + 14);

    // Value labels
    ctx.fillStyle = '#00ffe7';
    ctx.font = 'bold 8px Share Tech Mono, monospace';
    if (ph > 12) ctx.fillText(m.precision + '%', px + barW / 2, H - padB - ph - 3);
    ctx.fillStyle = '#5bc0ff';
    if (rh > 12) ctx.fillText(m.recall + '%', rx + barW / 2, H - padB - rh - 3);
  });

  // Legend
  const ly = H - 6;
  ctx.fillStyle = 'rgba(0,255,231,0.7)'; ctx.fillRect(W / 2 - 80, ly - 8, 10, 8);
  ctx.fillStyle = '#c8dff0'; ctx.font = '8px Share Tech Mono, monospace';
  ctx.textAlign = 'left'; ctx.fillText('Precision', W / 2 - 66, ly);
  ctx.fillStyle = 'rgba(0,136,255,0.7)'; ctx.fillRect(W / 2 + 10, ly - 8, 10, 8);
  ctx.fillStyle = '#c8dff0'; ctx.fillText('Recall', W / 2 + 24, ly);
}

// ---------------------------------------------------------------------------
// Auto-init on DOMContentLoaded
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  bindFileInput('fi',  'fn');
  bindFileInput('vf',  'vfn');
  bindFileInput('mfi', 'mfn');
});
