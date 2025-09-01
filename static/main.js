let ipChart = null;
let statusChart = null;
let busy = false;

function $(id) { return document.getElementById(id); }

function resetVisuals() {
  if (ipChart)  { ipChart.destroy();  ipChart = null; }
  if (statusChart) { statusChart.destroy(); statusChart = null; }
  const alerts = $('securityAlerts');
  if (alerts) alerts.textContent = 'Lade…';
}

function setCsvFormFromContent(content) {
  const form = $('csvForm');
  if (!form) return;
  form.innerHTML = '';
  const hidden = document.createElement('input');
  hidden.type = 'hidden';
  hidden.name = 'content';
  hidden.value = content;
  form.appendChild(hidden);
  const btn = document.createElement('button');
  btn.className = 'btn ghost';
  btn.id = 'btnCsv';
  btn.type = 'submit';
  btn.textContent = 'CSV exportieren';
  form.appendChild(btn);
}

function renderStats(data) {
  const ipCtx = $('ipChart').getContext('2d');
  const stCtx = $('statusChart').getContext('2d');

  const ipLabels = (data.top_ips || []).map(([ip, _]) => ip);
  const ipValues = (data.top_ips || []).map(([_, cnt]) => cnt);
  ipChart = new Chart(ipCtx, {
    type: 'bar',
    data: { labels: ipLabels, datasets: [{ label: 'Hits pro IP', data: ipValues }] },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });

  const st = (data.statuses || []).slice().sort((a,b)=>a[0]-b[0]);
  const stLabels = st.map(([code, _]) => code);
  const stValues = st.map(([_, cnt]) => cnt);
  statusChart = new Chart(stCtx, {
    type: 'line',
    data: { labels: stLabels, datasets: [{ label: 'Requests pro Statuscode', data: stValues, tension: .3 }] },
    options: { responsive: true }
  });

  const container = $('securityAlerts');
  const explained = data.alerts || [];
  if (explained.length === 0) {
    container.textContent = 'Keine Alerts gefunden.';
    return;
  }
  const html = explained.map(a => {
    const tag = a.severity === 'critical' ? 'tag-bad' : 'tag-warn';
    const reasons = (a.reasons || []).map(r => `<li>${r}</li>`).join('');
    const samples = (a.samples || []).map(s => `<code>${s}</code>`).join('<br>');
    const when = (a.first_ts || a.last_ts)
      ? `<div class="kv"><span>Zeitraum:</span><span>${a.first_ts || '—'} → ${a.last_ts || '—'}</span></div>`
      : '';
    return `
      <details class="alert-item">
        <summary>
          ${a.type} <strong>${a.ip}</strong> (${a.count})
          <span class="tag ${tag}">${a.severity === 'critical' ? 'kritisch' : 'verdächtig'}</span>
        </summary>
        <div class="alert-body">
          <ul class="reasons">${reasons}</ul>
          ${when}
          ${samples ? `<div class="kv"><span>Beispiele:</span><span>${samples}</span></div>` : ''}
        </div>
      </details>
    `;
  }).join('');
  container.innerHTML = html;
}

async function analyzeFile() {
  if (busy) return;
  const input = $('fileInput');
  const f = input && input.files[0];
  if (!f) return alert('Bitte zuerst eine Datei wählen.');
  busy = true; resetVisuals();

  try {
    const text = await f.text();
    const fd = new FormData();
    fd.append('file', new File([text], f.name, { type: 'text/plain' }));
    const res = await fetch('/analyze', { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) return alert(data.error || 'Fehler bei der Analyse.');
    renderStats(data);
    setCsvFormFromContent(text);
  } catch (e) {
    alert('Fehler: ' + e.message);
  } finally {
    if (input) input.value = '';
    busy = false;
  }
}

async function analyzeText() {
  if (busy) return;
  const content = ($('logText') && $('logText').value) || '';
  if (!content.trim()) return alert('Bitte Logtext einfügen.');
  busy = true; resetVisuals();

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ content })
    });
    const data = await res.json();
    if (!res.ok) return alert(data.error || 'Fehler bei der Analyse.');
    renderStats(data);
    setCsvFormFromContent(content);
  } catch (e) {
    alert('Fehler: ' + e.message);
  } finally {
    busy = false;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btnFile = $('btnAnalyzeFile');
  const btnText = $('btnAnalyzeText');
  if (btnFile) btnFile.addEventListener('click', analyzeFile);
  if (btnText) btnText.addEventListener('click', analyzeText);
});
