// NRG-Assessment GUI frontend.
// Vanilla JS. No frameworks, no bundler. CSP-friendly (no eval, no inline
// handlers, all wiring via addEventListener). Tested against the CSP
// emitted by Lib/Start-NRGWebServer.ps1.

(function () {
  'use strict';

  // ───────────────────────── helpers ──────────────────────────
  function $(id) { return document.getElementById(id); }

  function setStatus(text) { $('status').textContent = text; }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (ch) {
      return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch];
    });
  }

  async function jsonFetch(url, opts) {
    const res = await fetch(url, opts || {});
    if (!res.ok) throw new Error(url + ' → ' + res.status);
    return res.json();
  }

  // ─────────────────────── client list ─────────────────────────
  async function loadClients() {
    setStatus('Loading clients…');
    let clients = [];
    try { clients = await jsonFetch('/api/clients'); }
    catch (e) { setStatus('Client list unavailable'); return; }

    const list = $('client-list');
    list.replaceChildren();
    clients.forEach(function (c) {
      const card = document.createElement('div');
      card.className = 'card';
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');

      const title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = c.name || c.domain;
      card.appendChild(title);

      const meta = document.createElement('div');
      meta.className = 'card-meta';
      const bits = [c.domain, c.clientType].filter(Boolean).join(' · ');
      meta.textContent = bits;
      card.appendChild(meta);

      card.addEventListener('click', function () { triggerScan(c.domain, c.name); });
      card.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); triggerScan(c.domain, c.name); }
      });
      list.appendChild(card);
    });
    setStatus('Ready');
  }

  // ─────────────────────── prior runs ─────────────────────────
  async function loadRuns() {
    let runs = [];
    try { runs = await jsonFetch('/api/runs'); }
    catch (e) { /* empty list is fine */ }

    const list = $('run-list');
    list.replaceChildren();
    runs.forEach(function (r) {
      const row = document.createElement('div');
      row.className = 'run-item';
      row.setAttribute('role', 'button');
      row.setAttribute('tabindex', '0');

      const tenant = document.createElement('div');
      tenant.className = 'run-tenant';
      tenant.textContent = r.tenant;
      row.appendChild(tenant);

      const time = document.createElement('div');
      time.className = 'run-time';
      time.textContent = r.timestamp;
      row.appendChild(time);

      const size = document.createElement('div');
      size.className = 'run-size';
      size.textContent = (r.sizeKb || 0) + ' KB';
      row.appendChild(size);

      if (r.hasReport) {
        row.addEventListener('click', function () { openReport(r.tenant, r.id, r.timestamp); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openReport(r.tenant, r.id, r.timestamp); }
        });
      } else {
        row.style.opacity = '0.5';
        row.style.cursor = 'default';
      }
      list.appendChild(row);
    });
  }

  // ─────────────────────── scan trigger ────────────────────────
  function showProgressPanel(name) {
    $('panel-progress').hidden = false;
    $('progress-tenant').textContent = name ? ' ' + name : '';
    $('progress-fill').style.width = '0%';
    $('progress-log').textContent = '';
  }

  async function triggerScan(domain, displayName) {
    if (!domain) { setStatus('Enter a tenant domain first'); return; }
    if (!/^[A-Za-z0-9.\-]+$/.test(domain)) {
      setStatus('Invalid domain format');
      return;
    }
    if (!confirm('Run a full assessment of ' + (displayName || domain) + '?')) return;

    showProgressPanel(displayName || domain);
    setStatus('Starting scan…');

    let runId;
    try {
      const r = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain })
      });
      if (!r.ok) throw new Error(await r.text());
      runId = (await r.json()).runId;
    } catch (e) {
      setStatus('Could not start scan: ' + e.message);
      return;
    }

    setStatus('Scanning…');
    pollScan(runId, domain);
  }

  async function pollScan(runId, domain) {
    let backoffMs = 1000;
    while (true) {
      let s;
      try { s = await jsonFetch('/api/scan/' + encodeURIComponent(runId) + '/status'); }
      catch (e) { setStatus('Lost contact with server'); break; }

      // Update bar
      const pct = Math.max(0, Math.min(100, Number(s.percent) || 0));
      $('progress-fill').style.width = pct + '%';
      // Replace the log; we always render the trailing tail returned by the server.
      $('progress-log').textContent = (s.lines || []).join('\n');
      $('progress-log').scrollTop = $('progress-log').scrollHeight;

      if (s.status === 'completed') {
        setStatus('Scan complete');
        await loadRuns();
        if (s.resultId) {
          openReport(domain, s.resultId, '(just now)');
        }
        break;
      }
      if (s.status === 'failed') {
        setStatus('Scan failed — see log');
        break;
      }
      await new Promise(function (res) { setTimeout(res, backoffMs); });
    }
  }

  // ─────────────────────── report viewer ───────────────────────
  async function openReport(tenant, id, timestamp) {
    setStatus('Loading report…');
    const url = '/api/runs/' + encodeURIComponent(tenant) + '/' + encodeURIComponent(id) + '/report';
    let html;
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(res.status);
      html = await res.text();
    } catch (e) {
      setStatus('Could not load report');
      return;
    }
    $('panel-report').hidden = false;
    $('report-title').textContent = tenant + (timestamp ? ' — ' + timestamp : '');
    $('report-frame').srcdoc = html;
    setStatus('Ready');
    $('panel-report').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function closeReport() {
    $('panel-report').hidden = true;
    $('report-frame').srcdoc = '';
  }

  // ─────────────────────── wire-up ─────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    $('btn-refresh-clients').addEventListener('click', loadClients);
    $('btn-refresh-runs').addEventListener('click', loadRuns);
    $('btn-close-report').addEventListener('click', closeReport);
    $('btn-run-adhoc').addEventListener('click', function () {
      const v = $('adhoc-domain').value.trim();
      triggerScan(v, v);
    });
    $('adhoc-domain').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); $('btn-run-adhoc').click(); }
    });

    loadClients();
    loadRuns();
  });
})();
