/* =====================================================================
   HONEYTRAP SIEM - shared shell for every page (Slate skin)
   Exposes window.HT with helpers the page scripts use.
   All honeypot data is attacker controlled: pages must pass every value
   through HT.esc() before it touches innerHTML, and must never put data
   inside inline on* handlers (use data-* attributes + delegated listeners).
   ===================================================================== */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const root = document.documentElement;
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const hasGsap = typeof window.gsap !== "undefined";
  if (!hasGsap) root.classList.add("no-gsap");

  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) {} },
  };

  // ---------------- formatting ----------------
  const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const p2 = n => String(n).padStart(2, "0");
  function fmtTime(ts, withSeconds = true) {
    if (!ts) return "-";
    const d = new Date(ts); if (isNaN(d)) return "-";
    return `${MONTHS[d.getMonth()]} ${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}${withSeconds ? ":" + p2(d.getSeconds()) : ""}`;
  }
  function ago(ts) {
    if (!ts) return "never";
    const t = typeof ts === "number" ? ts : new Date(ts).getTime(); if (isNaN(t)) return "-";
    const s = Math.max(0, (Date.now() - t) / 1000);
    return s < 60 ? `${Math.floor(s)}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
  }
  const STATUSES = ["new", "investigating", "resolved"];
  const statusTag = s => { const st = STATUSES.includes(s) ? s : "new"; return `<span class="sev ${st}">${st}</span>`; };
  const sevTag = s => { const v = ["critical", "high", "medium", "low", "info"].includes(s) ? s : "info"; return `<span class="sev ${v}">${v}</span>`; };
  const railMark = s => `<span class="rail-mark ${esc(s || "info")}"></span>`;
  const mitreChip = t => t ? `<span class="chip mono" title="MITRE ATT&amp;CK ${esc(t)}">${esc(t)}</span>` : `<span class="dash">-</span>`;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;
  const skelRows = (n, cols) => Array.from({ length: n }, () =>
    `<tr class="skel-row">${Array.from({ length: cols }, (_, i) => `<td><span class="skel" style="width:${i === cols - 1 ? 70 : 40 + ((i * 37) % 50)}%"></span></td>`).join("")}</tr>`).join("");

  async function api(path, opts = {}) {
    const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
    if (res.status === 401 || res.redirected && res.url.includes("/login")) { location.href = "/login"; throw new Error("signed out"); }
    let data; try { data = await res.json(); } catch (e) { throw new Error("bad response"); }
    if (!res.ok || (data && data.error)) throw new Error((data && data.error) || `HTTP ${res.status}`);
    return data;
  }

  // time-range presets shared by dashboard + sessions
  const RANGE_MINUTES = { "15m": 15, "1h": 60, "24h": 1440, "7d": 10080, "30d": 43200 };
  function rangeParams(params, rangeSel, fromEl, toEl) {
    const range = rangeSel.value;
    if (range === "custom") {
      if (fromEl.value) params.set("date_from", new Date(fromEl.value).toISOString());
      if (toEl.value) params.set("date_to", new Date(toEl.value).toISOString());
    } else if (RANGE_MINUTES[range]) {
      params.set("date_from", new Date(Date.now() - RANGE_MINUTES[range] * 60000).toISOString());
    }
    return params;
  }

  // animated number change (count-up), skipped when motion is reduced
  const shown = new Map();
  function num(el, key, v) {
    if (!el) return;
    if (typeof v !== "number") { el.textContent = v; return; }
    const from = shown.has(key) ? shown.get(key) : v; shown.set(key, v);
    if (from === v || reduceMotion) { el.textContent = v.toLocaleString(); return; }
    const t0 = performance.now(), dur = 440;
    const step = t => { const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(from + (v - from) * e).toLocaleString(); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }

  // stagger rows in on the FIRST render only; polling refreshes stay still
  const entered = new Set();
  function enter(key, els) {
    if (entered.has(key)) return; entered.add(key);
    if (!hasGsap || reduceMotion || !els || !els.length) return;
    gsap.from(els, { autoAlpha: 0, y: 6, duration: .38, ease: "power2.out", stagger: { amount: Math.min(.32, els.length * .025) }, clearProps: "opacity,visibility,transform" });
  }

  // ---------------- toast ----------------
  function toast(message, opts = {}) {
    const stack = $("#toasts"); if (!stack) return { dismiss() {} };
    const el = document.createElement("div");
    el.className = "toast " + (opts.kind || "info");
    const lead = document.createElement("span");
    lead.className = opts.spinner ? "spin-i" : "dot";
    const msg = document.createElement("span"); msg.textContent = message;
    el.append(lead, msg);
    if (opts.linkText && opts.linkHref) { const a = document.createElement("a"); a.textContent = opts.linkText; a.href = opts.linkHref; el.appendChild(a); }
    stack.appendChild(el);
    requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add("show")));
    let gone = false;
    const dismiss = () => { if (gone) return; gone = true; el.classList.remove("show"); setTimeout(() => el.remove(), 260); };
    const timer = setTimeout(dismiss, opts.duration || 3200);
    el.addEventListener("click", e => { if (e.target.tagName !== "A") { clearTimeout(timer); dismiss(); } });
    return { dismiss: () => { clearTimeout(timer); dismiss(); } };
  }

  // ---------------- glass confirm modal (replaces window.confirm) ----------------
  function confirmBox({ title = "Are you sure?", message = "", okText = "OK", danger = false } = {}) {
    const wrap = $("#modal"); if (!wrap) return Promise.resolve(window.confirm(message));
    $("#modal-title").textContent = title; $("#modal-msg").textContent = message;
    const ok = $("#modal-ok"); ok.textContent = okText; ok.className = "btn primary" + (danger ? " danger" : "");
    wrap.hidden = false; requestAnimationFrame(() => wrap.classList.add("open"));
    const last = document.activeElement; setTimeout(() => ok.focus(), 30);
    return new Promise(resolve => {
      const close = v => { wrap.classList.remove("open"); setTimeout(() => { wrap.hidden = true; }, 220);
        wrap.removeEventListener("click", onClick); document.removeEventListener("keydown", onKey); if (last && last.focus) last.focus(); resolve(v); };
      const onClick = e => { if (e.target.closest("[data-modal-cancel]")) close(false); else if (e.target.closest("#modal-ok")) close(true); };
      const onKey = e => { if (e.key === "Escape") close(false); else if (e.key === "Enter") { e.preventDefault(); close(true); } };
      wrap.addEventListener("click", onClick); document.addEventListener("keydown", onKey);
    });
  }

  // ---------------- clock + live state ----------------
  let lastOk = Date.now();
  function tick() {
    const d = new Date(), c = $("#clock");
    if (c) c.textContent = `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}  ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} UTC`;
    const live = $("#live"); if (!live) return;
    const stale = Date.now() - lastOk > 20000;
    live.classList.toggle("stale", stale); $("#live-text").textContent = stale ? "STALE" : "LIVE";
  }

  // ---------------- HUD counters (top bar + rail badge) ----------------
  async function hud() {
    let h; try { h = await api("/api/hud"); lastOk = Date.now(); } catch (e) { return; }
    num($("#hud-events-v"), "hud-events", h.events);
    num($("#hud-alerts-v"), "hud-alerts", h.open_alerts);
    const hot = h.open_alerts > 0;
    $("#hud-alerts")?.classList.toggle("hot", hot);
    const b = $("#nav-alerts-bdg"); if (b) { b.hidden = !hot; b.textContent = h.open_alerts; }
    const le = $("#rail-last"); if (le) le.textContent = h.last_event ? ago(h.last_event) : "none yet";
  }

  // ---------------- page title animation ----------------
  const TITLE_FX = {
    rise: el => splitAnimate(el, { yPercent: 70, autoAlpha: 0, duration: .55, ease: "expo.out", stagger: .022 },
      (s, i) => s.animate([{ transform: "translateY(0.6em)", opacity: 0 }, { transform: "none", opacity: 1 }], { duration: 480, delay: i * 26, easing: "cubic-bezier(.16,1,.3,1)", fill: "backwards" })),
    blur: el => hasGsap ? gsap.from(el, { filter: "blur(12px)", autoAlpha: 0, letterSpacing: "0.08em", duration: .6, ease: "expo.out", clearProps: "all" })
      : el.animate([{ filter: "blur(12px)", opacity: 0 }, { filter: "blur(0)", opacity: 1 }], { duration: 560, easing: "cubic-bezier(.16,1,.3,1)" }),
    wipe: el => el.animate([{ clipPath: "inset(0 100% 0 0)" }, { clipPath: "inset(0 0% 0 0)" }], { duration: 520, easing: "cubic-bezier(.7,0,.2,1)" }),
    none: null,
  };
  function splitAnimate(el, gsapVars, waapi) {
    const text = el.textContent; el.setAttribute("aria-label", text);
    el.innerHTML = [...text].map(ch => `<span class="tch" aria-hidden="true">${ch === " " ? "&nbsp;" : esc(ch)}</span>`).join("");
    const chars = $$(".tch", el);
    const restore = () => { el.textContent = text; el.removeAttribute("aria-label"); };
    if (hasGsap) gsap.from(chars, { ...gsapVars, onComplete: restore });
    else { let last; chars.forEach((s, i) => { last = waapi(s, i); }); if (last) last.onfinish = restore; else restore(); }
  }
  function animateTitle(el, kind) {
    if (!el || reduceMotion) return;
    const fx = TITLE_FX[kind || store.get("ht-title", "rise")];
    if (fx) fx(el);
  }

  // ---------------- page entrance (GSAP, falls back to CSS) ----------------
  function pageEnter() {
    if (!hasGsap || reduceMotion) return;
    const kids = $$(".page > *").filter(el => !el.hidden);
    gsap.from(kids, { autoAlpha: 0, y: 10, duration: .45, ease: "power2.out", stagger: .06, clearProps: "opacity,visibility,transform" });
  }

  // ---------------- theme switch (View Transitions clip reveal) ----------------
  const TRANSITIONS = {
    circle:  { label: "Circle from the button", run: (x, y) => { const r = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
      return [{ clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${r}px at ${x}px ${y}px)`] }, { duration: 520, easing: "cubic-bezier(.4,0,.2,1)" }]; } },
    iris:    { label: "Iris from centre", run: () => [{ clipPath: ["inset(50% 50% 50% 50% round 40%)", "inset(0% 0% 0% 0% round 0%)"] }, { duration: 600, easing: "cubic-bezier(.16,1,.3,1)" }] },
    curtain: { label: "Curtain drop", run: () => [{ clipPath: ["inset(0 0 100% 0)", "inset(0 0 0% 0)"] }, { duration: 560, easing: "cubic-bezier(.7,0,.2,1)" }] },
    split:   { label: "Split from centre", run: () => [{ clipPath: ["inset(0 50% 0 50%)", "inset(0 0% 0 0%)"] }, { duration: 540, easing: "cubic-bezier(.16,1,.3,1)" }] },
    fade:    { label: "Crossfade", run: () => [{ opacity: [0, 1] }, { duration: 380, easing: "ease-out" }] },
    none:    { label: "Instant", run: null },
  };
  function applyTheme(t) { if (t === "light") root.dataset.theme = "light"; else delete root.dataset.theme; syncThemeBtn(); }
  function syncThemeBtn() { const b = $("#theme-toggle"); if (!b) return; const light = root.dataset.theme === "light"; b.title = light ? "Switch to dark mode" : "Switch to light mode"; }
  function switchTheme(next, x, y, kind) {
    const commit = () => { applyTheme(next); store.set("ht-theme", next || null); };
    const tr = TRANSITIONS[kind || store.get("ht-vt", "circle")] || TRANSITIONS.circle;
    if (reduceMotion || !document.startViewTransition || !tr.run) { commit(); return; }
    root.classList.add("vt-theme");
    const t = document.startViewTransition(commit);
    t.ready.then(() => { const [kf, opts] = tr.run(x, y); root.animate(kf, { ...opts, pseudoElement: "::view-transition-new(root)" }); }).catch(() => {});
    t.finished.finally(() => root.classList.remove("vt-theme"));
  }

  // ---------------- command palette (Ctrl K) ----------------
  function setupCmdk() {
    const wrap = $("#cmdk"), input = $("#cmdk-input"), list = $("#cmdk-list"); if (!wrap) return;
    let idx = 0, items = [];
    const candidates = () => [
      ...$$(".nav a[href]").map(a => ({ g: "Go to", l: a.querySelector(".label").textContent.trim(), run: () => { location.href = a.getAttribute("href"); } })),
      { g: "Action", l: "Switch theme", run: () => $("#theme-toggle")?.click() },
      { g: "Action", l: "Collapse or expand the sidebar", run: () => $("#rail-toggle")?.click() },
      { g: "Action", l: "Sign out", run: () => { location.href = "/logout"; } },
      ...(window.HT_CMDS || []),
    ];
    const render = () => {
      const q = input.value.trim().toLowerCase();
      items = q ? candidates().filter(i => i.l.toLowerCase().includes(q) || i.g.toLowerCase().includes(q)) : candidates().slice(0, 14);
      idx = Math.min(idx, Math.max(0, items.length - 1));
      list.innerHTML = items.length ? items.map((it, i) => `<li role="option" aria-selected="${i === idx}" class="${i === idx ? "on" : ""}" data-ci="${i}"><span class="cg">${esc(it.g)}</span><span>${esc(it.l)}</span>${it.h ? `<span class="ch">${esc(it.h)}</span>` : ""}</li>`).join("")
        : `<li class="cnone">Nothing matches "${esc(input.value)}"</li>`;
      list.querySelector(".on")?.scrollIntoView({ block: "nearest" });
    };
    const open = () => { wrap.hidden = false; input.value = ""; idx = 0; render(); input.focus(); requestAnimationFrame(() => wrap.classList.add("open")); };
    const close = () => { wrap.classList.remove("open"); setTimeout(() => { if (!wrap.classList.contains("open")) wrap.hidden = true; }, 160); };
    const run = i => { const it = items[i]; if (!it) return; close(); it.run(); };
    $("#cmdk-open")?.addEventListener("click", open);
    input.addEventListener("input", () => { idx = 0; render(); });
    input.addEventListener("keydown", e => {
      if (e.key === "ArrowDown") { e.preventDefault(); idx = Math.min(items.length - 1, idx + 1); render(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); idx = Math.max(0, idx - 1); render(); }
      else if (e.key === "Enter") { e.preventDefault(); run(idx); }
      else if (e.key === "Escape") close();
    });
    list.addEventListener("mousemove", e => { const li = e.target.closest("[data-ci]"); if (li && +li.dataset.ci !== idx) { idx = +li.dataset.ci; render(); } });
    list.addEventListener("mousedown", e => { const li = e.target.closest("[data-ci]"); if (li) { e.preventDefault(); run(+li.dataset.ci); } });
    wrap.addEventListener("mousedown", e => { if (e.target.matches("[data-cmdk-close]")) close(); });
    document.addEventListener("keydown", e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); wrap.hidden ? open() : close(); } });
  }

  // ---------------- boot ----------------
  function boot() {
    syncThemeBtn();
    const tb = $("#theme-toggle");
    if (tb) tb.addEventListener("click", () => {
      const r = tb.getBoundingClientRect();
      switchTheme(root.dataset.theme === "light" ? "" : "light", r.left + r.width / 2, r.top + r.height / 2);
    });
    const rt = $("#rail-toggle");
    if (rt) {
      const sync = () => { const c = root.dataset.rail === "collapsed"; rt.title = c ? "Expand sidebar" : "Collapse sidebar"; rt.setAttribute("aria-label", rt.title); };
      sync();
      rt.addEventListener("click", () => { const c = root.dataset.rail === "collapsed";
        if (c) delete root.dataset.rail; else root.dataset.rail = "collapsed";
        store.set("ht-rail", c ? null : "collapsed"); sync(); });
    }
    $$(".nav a").forEach(a => a.addEventListener("click", () => { a.classList.remove("ripple"); void a.offsetWidth; a.classList.add("ripple"); }));
    setupCmdk();
    tick(); setInterval(tick, 500);
    if ($("#hud-events-v")) { hud(); setInterval(() => { if (!document.hidden) hud(); }, 5000); }
    animateTitle($(".page .h h1"));
    pageEnter();
  }

  window.HT = { $, $$, esc, fmtTime, ago, api, toast, confirm: confirmBox, statusTag, sevTag, railMark, mitreChip, plural, skelRows, rangeParams, num, enter, store,
    animateTitle, switchTheme, TRANSITIONS, TITLE_FX, reduceMotion, hasGsap, STATUSES };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
