// TenantPosture GUI frontend. A viewer: it lists past runs and opens their
// reports. It starts no scan and sends no request but GET (an assessment is run
// from the command line).
// Vanilla JS. No frameworks, no bundler. CSP-friendly (no eval, no inline
// handlers, all wiring via addEventListener). Tested against the CSP
// emitted by Lib/Start-TPWebServer.ps1.

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

  // ─────────────────────── prior runs ─────────────────────────
  // Where the multi-page report site for a run is served. `folder` is the
  // address segment from /api/runs (the tenant folder, or the reserved segment
  // for a command-line run), never the display label.
  function siteUrl(run) {
    return '/site/' + encodeURIComponent(run.folder) + '/' + encodeURIComponent(run.id) + '/index.html';
  }

  // The fields the viewer needs from a row of /api/runs. Older servers sent only
  // `tenant`, which was the folder name then.
  function toRun(r) {
    return { folder: r.folder || r.tenant, id: r.id, tenant: r.tenant, timestamp: r.timestamp, hasSite: !!r.hasSite };
  }

  // Returns the list it rendered.
  async function loadRuns() {
    let runs = [];
    try { runs = await jsonFetch('/api/runs'); }
    catch (e) { /* empty list is fine */ }
    if (!Array.isArray(runs)) runs = [];

    const list = $('run-list');
    list.replaceChildren();
    runs.forEach(function (r) {
      const run = toRun(r);

      const wrap = document.createElement('div');
      wrap.className = 'run-row';

      // The clickable part (opens the single-page report). The site link is a
      // sibling, not a child: an anchor nested in a role=button would also fire
      // the button's key handler.
      const row = document.createElement('div');
      row.className = 'run-item';
      row.setAttribute('role', 'button');
      row.setAttribute('tabindex', '0');

      const tenant = document.createElement('div');
      tenant.className = 'run-tenant';
      tenant.textContent = r.tenant;
      if (r.layout === 'flat') {
        const origin = document.createElement('span');
        origin.className = 'run-origin';
        origin.textContent = ' · command line';
        tenant.appendChild(origin);
      }
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
        row.addEventListener('click', function () { openReport(run); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openReport(run); }
        });
      } else {
        row.style.opacity = '0.5';
        row.style.cursor = 'default';
      }
      wrap.appendChild(row);

      if (run.hasSite) {
        // New tab: the server forbids framing (frame-ancestors 'none'), and the
        // site is a multi-page document that wants the whole window anyway.
        const site = document.createElement('a');
        site.className = 'run-site';
        site.textContent = 'Report site';
        site.href = siteUrl(run);
        site.target = '_blank';
        site.rel = 'noopener';
        wrap.appendChild(site);
      }
      list.appendChild(wrap);
    });
    return runs;
  }

  // ─────────────────────── report viewer ───────────────────────
  // `run` is a row from /api/runs: { folder, id, tenant, timestamp, hasSite }.
  async function openReport(run) {
    setStatus('Loading report…');
    const url = '/api/runs/' + encodeURIComponent(run.folder) + '/' + encodeURIComponent(run.id) + '/report';
    $('panel-report').hidden = false;
    $('report-title').textContent = run.tenant + (run.timestamp ? ' — ' + run.timestamp : '');
    // Loaded through src, never srcdoc: a srcdoc document inherits THIS page's
    // policy and discards the report response's, so the per-run image policy
    // the server sets for the report (its own brand's logo origin) would never
    // apply. Through src, the response's own headers govern the framed document.
    // One request only: a refusal (404/400) arrives as JSON, which the frame
    // (same-origin by its sandbox) shows as a non-HTML document; that is the
    // failure signal, read on load, instead of a probe that fetched the whole
    // report a second time.
    const frame = $('report-frame');
    frame.removeAttribute('srcdoc');
    frame.onload = function () {
      let ok = true;
      try {
        const doc = frame.contentDocument;
        ok = !!doc && doc.contentType === 'text/html';
      } catch (e) { ok = true; }
      if (!ok) {
        // The handler is cleared first: about:blank loads as text/html and
        // would otherwise run it again and overwrite the message.
        frame.onload = null;
        frame.src = 'about:blank';
        $('panel-report').hidden = true;
        setStatus('Could not load report');
        return;
      }
      setStatus('Ready');
    };
    frame.src = url;
    const site = $('link-report-site');
    if (run.hasSite) {
      site.href = siteUrl(run);
      site.hidden = false;
    } else {
      site.removeAttribute('href');
      site.hidden = true;
    }
    $('panel-report').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function closeReport() {
    $('panel-report').hidden = true;
    const frame = $('report-frame');
    frame.onload = null;
    frame.src = 'about:blank';
    $('link-report-site').hidden = true;
  }

  // ─────────────────────── wire-up ─────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    $('btn-refresh-runs').addEventListener('click', loadRuns);
    $('btn-close-report').addEventListener('click', closeReport);
    loadRuns();
  });
})();
