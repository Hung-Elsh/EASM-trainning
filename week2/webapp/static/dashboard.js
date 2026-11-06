// Plain JS dashboard. All API data is inserted via textContent / createElement only
// (scan results are untrusted); never build HTML strings here.
'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
let allFindings = [];
const charts = [];

function $(id) { return document.getElementById(id); }

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

async function getJSON(url) {
  const resp = await fetch(url, { headers: { Accept: 'application/json' } });
  let body = null;
  try { body = await resp.json(); } catch (e) { /* non-JSON body */ }
  if (!resp.ok) {
    throw new Error((body && body.error) || ('Request failed: ' + url + ' (' + resp.status + ')'));
  }
  return body;
}

function showError(message) {
  const banner = $('error-banner');
  banner.textContent = message;
  banner.hidden = false;
  $('content').hidden = true;
}

// ---- header and tiles ----

function renderTiles(summary, score) {
  $('last-scan').textContent = summary.generated_at || '-';
  $('tile-score').textContent = score.score;
  $('tile-hosts').textContent = summary.hosts;
  $('tile-services').textContent = summary.services;
  $('tile-critical').textContent = summary.by_severity.critical || 0;
  $('tile-high').textContent = summary.by_severity.high || 0;
}

// ---- charts ----

function barChart(canvasId, labels, values, colors, valueTitle) {
  const text = cssVar('--text-2');
  const grid = cssVar('--grid');
  const chart = new Chart($(canvasId), {
    type: 'bar',
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderRadius: 4, maxBarThickness: 22 }] },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, title: { display: true, text: valueTitle, color: text }, ticks: { color: text, precision: 0 }, grid: { color: grid } },
        y: { ticks: { color: text }, grid: { display: false } },
      },
    },
  });
  charts.push(chart);
}

function renderCharts(summary) {
  // severity: fixed order, one hue stepped by severity
  barChart('chart-severity', SEVERITIES, SEVERITIES.map(s => summary.by_severity[s] || 0),
    SEVERITIES.map(s => cssVar('--sev-' + s)), 'Findings');

  const services = summary.top_services || [];
  barChart('chart-services', services.map(s => s.name || '(unknown)'), services.map(s => s.count),
    cssVar('--bar'), 'Open ports');

  const ports = summary.riskiest_ports || [];
  barChart('chart-ports', ports.map(p => p.ip + ':' + p.port + '/' + p.protocol), ports.map(p => p.penalty),
    cssVar('--bar'), 'Penalty');
}

// ---- findings table ----

function severityBadge(severity) {
  const known = SEVERITIES.includes(severity) ? severity : 'info';
  return el('span', severity, 'badge badge-' + known);
}

function findingRow(f) {
  const tr = document.createElement('tr');
  const sev = document.createElement('td');
  sev.appendChild(severityBadge(f.severity));
  tr.appendChild(sev);
  tr.appendChild(el('td', f.port + '/' + f.protocol, 'nowrap'));
  tr.appendChild(el('td', f.title));
  tr.appendChild(el('td', f.evidence, 'evidence'));
  tr.appendChild(el('td', f.confidence, 'nowrap'));
  tr.appendChild(el('td', f.remediation));
  return tr;
}

function renderFindings() {
  const sev = $('filter-severity').value;
  const conf = $('filter-confidence').value;
  const rows = allFindings.filter(f => (!sev || f.severity === sev) && (!conf || f.confidence === conf));
  const body = document.querySelector('#findings-table tbody');
  body.replaceChildren(...rows.map(findingRow));
  $('findings-count').textContent = '(' + rows.length + ' of ' + allFindings.length + ')';
}

// ---- hosts ----

function servicesTable(services) {
  const table = document.createElement('table');
  const head = document.createElement('tr');
  ['Port', 'State', 'Service', 'Product', 'Version'].forEach(h => head.appendChild(el('th', h)));
  const thead = document.createElement('thead');
  thead.appendChild(head);
  const tbody = document.createElement('tbody');
  services.forEach(s => {
    const tr = document.createElement('tr');
    tr.appendChild(el('td', s.port + '/' + s.protocol, 'nowrap'));
    tr.appendChild(el('td', s.state));
    tr.appendChild(el('td', s.name));
    tr.appendChild(el('td', s.product));
    tr.appendChild(el('td', s.version));
    tbody.appendChild(tr);
  });
  table.append(thead, tbody);
  return table;
}

function hostBlock(asset, hostScore) {
  const box = el('div', null, 'host card');
  let title = asset.ip;
  if (hostScore) title += '  (score ' + hostScore.score + ', ' + hostScore.findings + ' findings)';
  box.appendChild(el('h3', title));
  const names = el('ul', null, 'names');
  (asset.names || []).forEach(n => names.appendChild(el('li', n)));
  box.appendChild(names);
  const wrap = el('div', null, 'table-scroll hosts-scroll');
  wrap.appendChild(servicesTable(asset.services || []));
  box.appendChild(wrap);
  return box;
}

function renderHosts(assets, score) {
  const byIp = {};
  (score.hosts || []).forEach(h => { byIp[h.ip] = h; });
  $('hosts').replaceChildren(...assets.map(a => hostBlock(a, byIp[a.ip])));
}

// ---- main ----

async function init() {
  try {
    const [summary, assets, findings, score] = await Promise.all([
      getJSON('/api/summary'), getJSON('/api/assets'), getJSON('/api/findings'), getJSON('/api/score'),
    ]);
    renderTiles(summary, score);
    renderCharts(summary);
    allFindings = findings.findings || [];
    renderFindings();
    renderHosts(assets.assets || [], score);
  } catch (err) {
    charts.forEach(c => c.destroy());
    showError(err.message);
  }
}

$('filter-severity').addEventListener('change', renderFindings);
$('filter-confidence').addEventListener('change', renderFindings);
init();
