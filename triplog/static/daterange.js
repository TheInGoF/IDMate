/* ── Shared date-range picker (Grafana-style) ───────────────────────────────
 *
 * One picker for Trips, Charges and Analysis. The chosen range lives in the
 * Flask session (global keys date_from/date_to, written by POST /api/daterange)
 * — NOT in localStorage. Reset writes an empty range so the session is cleared
 * cleanly instead of silently restoring the old one (that was the "jumps back
 * to the same range" bug).
 *
 * Markup: see templates/_daterange.html. Input ids stay dateFrom/dateTo so the
 * existing page code (analysis loadAnalysis, trips export links, …) keeps
 * working unchanged.
 *
 * Per-page apply hook: if window.onDateRangeApply(from,to) exists it is called
 * after the range is stored (Analysis uses it to re-fetch via AJAX); otherwise
 * the page is reloaded so the server re-renders with the new range.
 */
(function () {
  'use strict';

  function pad(n) { return String(n).padStart(2, '0'); }
  function iso(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }

  // Compute {from,to} (inclusive, ISO) for a preset key. 'all' clears the range.
  function computePreset(key) {
    var now = new Date();
    var y = now.getFullYear(), m = now.getMonth(), d = now.getDate();
    var today = new Date(y, m, d);
    var from, to = today, dow;
    switch (key) {
      case 'today': from = today; break;
      case 'yesterday': from = new Date(y, m, d - 1); to = new Date(y, m, d - 1); break;
      case 'last7': from = new Date(y, m, d - 6); break;
      case 'last30': from = new Date(y, m, d - 29); break;
      case 'last90': from = new Date(y, m, d - 89); break;
      case 'last365': from = new Date(y, m - 12, d + 1); break;   // ~ last 12 months
      case 'thisWeek': dow = (now.getDay() + 6) % 7; from = new Date(y, m, d - dow); break;   // Mon-based
      case 'lastWeek':
        dow = (now.getDay() + 6) % 7;
        to = new Date(y, m, d - dow - 1);
        from = new Date(to.getFullYear(), to.getMonth(), to.getDate() - 6);
        break;
      case 'thisMonth': from = new Date(y, m, 1); break;
      case 'lastMonth': from = new Date(y, m - 1, 1); to = new Date(y, m, 0); break;
      case 'thisYear': from = new Date(y, 0, 1); break;
      case 'lastYear': from = new Date(y - 1, 0, 1); to = new Date(y - 1, 11, 31); break;
      case 'all': return { from: '', to: '' };
      default: return null;
    }
    return { from: iso(from), to: iso(to) };
  }

  var PRESET_KEYS = ['today', 'yesterday', 'last7', 'last30', 'last90', 'last365',
    'thisWeek', 'lastWeek', 'thisMonth', 'lastMonth', 'thisYear', 'lastYear'];

  function el(id) { return document.getElementById(id); }
  function root() { return el('drp'); }

  function setInputs(from, to) {
    var f = el('dateFrom'), t = el('dateTo');
    if (f) f.value = from || '';
    if (t) t.value = to || '';
  }

  function close() {
    var r = root();
    if (r) { r.classList.remove('open'); r.querySelector('.drp-toggle').setAttribute('aria-expanded', 'false'); }
  }

  // Which preset (if any) the current from/to corresponds to — for label + highlight.
  function matchPreset(fv, tv) {
    if (!fv && !tv) return 'all';
    for (var i = 0; i < PRESET_KEYS.length; i++) {
      var r = computePreset(PRESET_KEYS[i]);
      if (r && r.from === fv && r.to === tv) return PRESET_KEYS[i];
    }
    return null;
  }

  function fmtDisp(s) {
    if (!s) return '…';
    var d = new Date(s + 'T00:00:00');
    var loc = document.documentElement.lang || undefined;
    try { return d.toLocaleDateString(loc, { day: '2-digit', month: '2-digit', year: 'numeric' }); }
    catch (e) { return s; }
  }

  function updateLabel() {
    var r = root(); if (!r) return;
    var lbl = el('drpLabel'); if (!lbl) return;
    var fv = (el('dateFrom') || {}).value || '';
    var tv = (el('dateTo') || {}).value || '';
    var pk = matchPreset(fv, tv);
    if (pk === 'all' || (!fv && !tv)) { lbl.textContent = r.getAttribute('data-all-label') || '—'; return; }
    if (pk) {
      var btn = r.querySelector('.drp-preset[data-key="' + pk + '"]');
      if (btn) { lbl.textContent = btn.textContent.trim(); return; }
    }
    lbl.textContent = fmtDisp(fv) + ' – ' + fmtDisp(tv);
  }

  function syncActive() {
    var r = root(); if (!r) return;
    var fv = (el('dateFrom') || {}).value || '';
    var tv = (el('dateTo') || {}).value || '';
    var pk = matchPreset(fv, tv);
    r.querySelectorAll('.drp-preset').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-key') === pk);
    });
  }

  function apply(from, to) {
    fetch('/api/daterange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: from, to: to })
    }).then(function () {
      if (typeof window.onDateRangeApply === 'function') {
        window.onDateRangeApply(from, to);
        close(); updateLabel(); syncActive();
      } else {
        location.reload();
      }
    });
  }

  // ── Public (CSP-delegated) handlers ──
  window.drpToggle = function (e) {
    if (e) e.stopPropagation();
    var r = root(); if (!r) return;
    var open = r.classList.toggle('open');
    r.querySelector('.drp-toggle').setAttribute('aria-expanded', open ? 'true' : 'false');
  };

  window.drpPreset = function (key) {
    var rg = computePreset(key);
    if (!rg) return;
    setInputs(rg.from, rg.to);
    apply(rg.from, rg.to);
  };

  window.drpApply = function () {
    var fv = (el('dateFrom') || {}).value || '';
    var tv = (el('dateTo') || {}).value || '';
    if (!fv || !tv) return;          // custom range needs both ends
    if (fv > tv) { var tmp = fv; fv = tv; tv = tmp; setInputs(fv, tv); }
    apply(fv, tv);
  };

  // ── Wiring ──
  document.addEventListener('click', function (e) {
    var r = root();
    if (r && r.classList.contains('open') && !r.contains(e.target)) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });

  function boot() {
    if (!root()) return;            // page without a picker
    updateLabel();
    syncActive();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
