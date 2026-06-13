// idmate.js — geteilte UI-Helfer (FIXES 6.6, Fundament fuer 12.7)
// Global verfuegbar auf allen Seiten via _base.html (<script defer>).
// Bewusst KEINE IIFE/Modul-Kapselung: einfache globale Funktionsdeklarationen
// sind idempotent — wird die Datei (oder eine Seite mit lokaler Kopie) doppelt
// definiert, ist die letzte Deklaration wirksam, ohne Laufzeitfehler. Da diese
// Datei per defer NACH den Inline-Skripten laeuft, ueberschreibt sie etwaige
// lokale Kopien identitaetsgleich (gleiche Semantik) — kein Verhalten aendert sich.

// ── HTML-Escaper ──────────────────────────────────────────────
// Wandelt & < > " ' in HTML-Entities; nicht-string/leere Eingabe -> ''.
function escapeHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Alias, damit Seiten die bereits esc() nutzen kompatibel bleiben.
function esc(s) {
  return escapeHtml(s);
}

// ── Toast-CSS (selbst-injizierend, idempotent) ────────────────
// Injiziert das Toast-Styling EINMALIG, damit toast() auf jeder Seite ohne
// idmate.css-Aenderung funktioniert. id-Guard verhindert Doppel-Injektion.
// 1:1 uebernommen aus admin.html (.toast-container/.toast/.error/.success +
// prefers-reduced-motion).
function _idmateInjectToastCss() {
  if (document.getElementById('idmate-toast-css')) return;
  var style = document.createElement('style');
  style.id = 'idmate-toast-css';
  style.textContent =
    '.toast-container{position:fixed;left:50%;bottom:1.2rem;transform:translateX(-50%);z-index:11000;display:flex;flex-direction:column;gap:0.5rem;align-items:center;max-width:92vw;pointer-events:none}' +
    '.toast{pointer-events:auto;background:var(--bg-card);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:8px;padding:0.6rem 0.9rem;color:var(--text-1);font-size:0.85rem;line-height:1.35;box-shadow:0 6px 20px rgba(0,0,0,0.45);max-width:420px;word-wrap:break-word;opacity:0;transform:translateY(12px);transition:opacity .25s ease,transform .25s ease}' +
    '.toast.show{opacity:1;transform:translateY(0)}' +
    '.toast.error{border-left-color:var(--danger)}' +
    '.toast.success{border-left-color:var(--success-btn)}' +
    '@media (prefers-reduced-motion: reduce){.toast{transform:none;transition:opacity .15s linear}.toast.show{transform:none}}';
  (document.head || document.documentElement).appendChild(style);
}

// ── Toast ─────────────────────────────────────────────────────
// Nicht-blockierende Benachrichtigung (ersetzt alert()).
// type: 'error' (rot), 'success' (gruen), sonst neutral/info (blau).
// Leere/undefined message -> nichts. textContent => XSS-sicher.
function toast(message, type) {
  if (message === undefined || message === null || message === '') return;
  _idmateInjectToastCss();
  var container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  var el = document.createElement('div');
  el.className = 'toast' + (type === 'error' ? ' error' : type === 'success' ? ' success' : '');
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
  el.textContent = String(message);
  container.appendChild(el);
  // Reflow erzwingen, damit die Einblend-Transition greift.
  requestAnimationFrame(function () {
    requestAnimationFrame(function () { el.classList.add('show'); });
  });
  var remove = function () {
    el.classList.remove('show');
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 300);
  };
  setTimeout(remove, 3000);
}

// ── confirmModal-CSS (selbst-injizierend, idempotent) ─────────
// Eigene, prefixe Klassen (idmate-confirm-*), damit das Modal auf JEDER Seite
// gleich aussieht — unabhaengig von page-spezifischem oder idmate.css-.modal/.btn-*.
// (idmate.css definiert bereits .modal/.btn-danger, aber abweichend von der
// admin.html-Vorlage; deshalb hier bewusst gekapselte Klassen statt Reuse.)
// id-Guard verhindert Doppel-Injektion. Dark-Theme-Tokens + prefers-reduced-motion.
function _idmateInjectConfirmCss() {
  if (document.getElementById('idmate-confirm-css')) return;
  var style = document.createElement('style');
  style.id = 'idmate-confirm-css';
  style.textContent =
    '.idmate-confirm-bg{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:12000;display:none;justify-content:center;align-items:center}' +
    '.idmate-confirm-bg.open{display:flex}' +
    '.idmate-confirm{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;max-width:450px;width:90%;box-shadow:0 8px 28px rgba(0,0,0,.5);transform:translateY(8px);transition:transform .18s ease}' +
    '.idmate-confirm-bg.open .idmate-confirm{transform:translateY(0)}' +
    '.idmate-confirm p{font-size:0.9rem;color:var(--text-1);line-height:1.4;margin:0 0 0.8rem}' +
    '.idmate-confirm .idmate-confirm-btns{display:flex;gap:0.5rem;justify-content:flex-end;margin-top:0.6rem}' +
    '.idmate-confirm .idmate-confirm-btns button{padding:0.4rem 0.8rem;border-radius:6px;border:1px solid var(--border);font-size:0.85rem;cursor:pointer}' +
    '.idmate-confirm .idmate-confirm-cancel{background:var(--bg-hover);color:var(--text-1)}' +
    '.idmate-confirm .idmate-confirm-cancel:hover{background:var(--bg-active)}' +
    '.idmate-confirm .idmate-confirm-ok{background:var(--danger-btn);border-color:var(--danger);color:#fff}' +
    '.idmate-confirm .idmate-confirm-ok:hover{background:var(--danger)}' +
    '.idmate-confirm .idmate-confirm-ok:focus-visible,.idmate-confirm .idmate-confirm-cancel:focus-visible{outline:2px solid var(--accent);outline-offset:2px}' +
    '@media (prefers-reduced-motion: reduce){.idmate-confirm{transform:none;transition:none}.idmate-confirm-bg.open .idmate-confirm{transform:none}}';
  (document.head || document.documentElement).appendChild(style);
}

// ── confirmModal ──────────────────────────────────────────────
// Promise-basierter Ersatz fuer das blockierende native confirm().
// Aufruf-Muster: `if (!await confirmModal(msg)) return;`
//   OK / Enter            -> resolve(true)
//   Abbrechen / Escape    -> resolve(false)
//   Backdrop-Klick        -> resolve(false)  (drift-sicher: mousedown UND click)
// Self-contained: erzeugt sein DOM lazy einmalig (wiederverwendet danach) und
// haengt es an document.body — funktioniert ohne seitenspezifisches #confirmModal.
// Button-Labels i18n via window.IDMATE_LABELS.ok / .cancel (Fallback DE).
// Message via textContent => XSS-sicher. Auf der admin-Seite ueberschreibt diese
// (defer-)Version die lokale, mit identischer true/false-Semantik.
var _idmateConfirmRefs = null;
function _idmateBuildConfirm() {
  if (_idmateConfirmRefs) return _idmateConfirmRefs;
  _idmateInjectConfirmCss();
  var bg = document.createElement('div');
  bg.className = 'idmate-confirm-bg';
  bg.setAttribute('role', 'dialog');
  bg.setAttribute('aria-modal', 'true');
  var box = document.createElement('div');
  box.className = 'idmate-confirm';
  var msg = document.createElement('p');
  var btns = document.createElement('div');
  btns.className = 'idmate-confirm-btns';
  var cancelBtn = document.createElement('button');
  cancelBtn.className = 'idmate-confirm-cancel';
  cancelBtn.type = 'button';
  var okBtn = document.createElement('button');
  okBtn.className = 'idmate-confirm-ok';
  okBtn.type = 'button';
  btns.appendChild(cancelBtn);
  btns.appendChild(okBtn);
  box.appendChild(msg);
  box.appendChild(btns);
  bg.appendChild(box);
  document.body.appendChild(bg);
  _idmateConfirmRefs = { bg: bg, msg: msg, okBtn: okBtn, cancelBtn: cancelBtn };
  return _idmateConfirmRefs;
}

function confirmModal(message) {
  return new Promise(function (resolve) {
    var r = _idmateBuildConfirm();
    var bg = r.bg, okBtn = r.okBtn, cancelBtn = r.cancelBtn;
    var labels = window.IDMATE_LABELS || {};
    okBtn.textContent = labels.ok || 'OK';
    cancelBtn.textContent = labels.cancel || 'Abbrechen';
    r.msg.textContent = String(message == null ? '' : message);
    bg.classList.add('open');
    okBtn.focus();
    var done = false;
    var downOnSelf = false;
    var finish = function (result) {
      if (done) return; done = true;
      bg.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      bg.removeEventListener('mousedown', onDown);
      bg.removeEventListener('click', onBg);
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };
    var onOk = function () { finish(true); };
    var onCancel = function () { finish(false); };
    // Backdrop-Klick = Abbrechen, drift-sicher (mousedown UND click auf bg)
    var onDown = function (e) { downOnSelf = (e.target === bg); };
    var onBg = function (e) { if (e.target === bg && downOnSelf) finish(false); };
    var onKey = function (e) {
      if (e.key === 'Escape') finish(false);
      else if (e.key === 'Enter') { e.preventDefault(); finish(true); }
    };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    bg.addEventListener('mousedown', onDown);
    bg.addEventListener('click', onBg);
    document.addEventListener('keydown', onKey);
  });
}

// ── CSP-sichere Event-Delegation (FIXES 7.2) ──────────────────
// Ersetzt Inline-Handler-Attribute (onclick= etc.), die eine CSP ohne
// 'unsafe-inline' blockiert. Markup-Konvention:
//   <button data-onclick="fnName" data-args='[1,"x"]'>
// Der Dispatcher ruft window.fnName.call(element, ...args, event) auf —
// `this` ist wie beim Inline-Handler das Element, das Event haengt als
// LETZTES Zusatzargument an (Funktionen ohne Event-Parameter ignorieren es).
// data-args ist ein JSON-Array (optional). Kein eval/Function noetig.
(function () {
  function dispatch(ev, attr) {
    var el = ev.target && ev.target.closest && ev.target.closest('[' + attr + ']');
    if (!el) return;
    var name = el.getAttribute(attr);
    var fn = window[name];
    if (typeof fn !== 'function') {
      console.error('idmate-delegate: window.' + name + ' ist keine Funktion (' + attr + ')');
      return;
    }
    var args = [];
    var raw = el.getAttribute('data-args');
    if (raw) {
      try { args = JSON.parse(raw); }
      catch (e) { console.error('idmate-delegate: data-args kein JSON:', raw); return; }
    }
    fn.apply(el, args.concat([ev]));
  }
  // Bubble-Phase fuer Events, die bubbeln (gleiche Reihenfolge-Semantik wie
  // Inline-Handler); Capture nur fuer focus/blur (bubbeln nicht).
  ['click', 'change', 'input', 'keydown', 'submit', 'mouseover'].forEach(function (t) {
    document.addEventListener(t, function (ev) { dispatch(ev, 'data-on' + t); }, false);
  });
  ['focus', 'blur'].forEach(function (t) {
    document.addEventListener(t, function (ev) { dispatch(ev, 'data-on' + t); }, true);
  });
})();

// Kleiner benannter Helfer fuer ehemals inline "event.stopPropagation()":
// <span data-onclick="stopProp"> — Event kommt als letztes Argument.
function stopProp(ev) { ev.stopPropagation(); }
