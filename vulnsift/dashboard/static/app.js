/* VulnSift dashboard client. Vanilla JS, no external dependencies.
 *
 * Safety rule: every untrusted string that reaches innerHTML goes through esc().
 * URLs from reports are only rendered as links when they are http(s) (safeUrl()).
 */
"use strict";

(() => {
  // Mirrors vulnsift.models.HIGH_RISK_THRESHOLD / MEDIUM_RISK_THRESHOLD.
  const HIGH = 7;
  const MEDIUM = 4;
  const PAGE_SIZE = 25;
  const BAND_LABEL = { high: "High", medium: "Medium", low: "Low" };
  const STATUS_LABEL = { actionable: "Actionable", fp: "False positive", error: "Triage error" };

  const $ = (id) => document.getElementById(id);

  const state = {
    project: null,
    scan: null,
    finding: null,
    projects: [],
    scans: [],
    gen: 0,
    fgen: 0,
    lastFocus: null,
    explorer: { q: "", band: "", status: "all", sort: "risk", offset: 0, limit: PAGE_SIZE },
  };

  // ------------------------------------------------------------------ helpers

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function safeUrl(value) {
    try {
      const url = new URL(String(value ?? "").trim());
      return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
    } catch {
      return null;
    }
  }

  function linkOrText(value, label) {
    const href = safeUrl(value);
    const text = esc(label ?? value);
    if (!href) return text;
    return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
  }

  function num(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }

  function bandOf(score) {
    const s = num(score);
    if (s >= HIGH) return "high";
    if (s >= MEDIUM) return "medium";
    return "low";
  }

  function fmtDate(value, opts) {
    if (!value) return "-";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return opts ? d.toLocaleDateString(undefined, opts) : d.toLocaleString();
  }

  function fmtCost(value) {
    if (value === null || value === undefined || value === "") return "-";
    const n = num(value, NaN);
    if (!Number.isFinite(n)) return "-";
    return `$${n.toFixed(n < 0.01 ? 4 : 2)}`;
  }

  function signed(n) {
    const v = num(n);
    return v > 0 ? `+${v}` : String(v);
  }

  function riskBadge(score, status = "actionable") {
    if (status === "error") return '<span class="risk-badge risk-error"><b>!</b> Not assessed</span>';
    if (status === "fp") return `<span class="risk-badge risk-fp"><b>${esc(num(score))}</b> FP</span>`;
    const band = bandOf(score);
    return `<span class="risk-badge risk-${band}"><b>${esc(num(score))}</b> ${BAND_LABEL[band]}</span>`;
  }

  function statusBadge(status) {
    const key = STATUS_LABEL[status] ? status : "actionable";
    return `<span class="status-badge status-${key}">${esc(STATUS_LABEL[key])}</span>`;
  }

  function location(file, line, endLine) {
    if (!file) return "-";
    let loc = String(file);
    if (line) loc += `:${num(line)}`;
    if (line && endLine && num(endLine) !== num(line)) loc += `-${num(endLine)}`;
    return loc;
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  // ------------------------------------------------------------------ API + banners

  class HttpError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function api(path, params = {}) {
    const url = new URL(path, window.location.origin);
    for (const [k, v] of Object.entries(params)) {
      if (v !== null && v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
    let response;
    try {
      response = await fetch(url, {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch {
      throw new HttpError(0, "network error - is the dashboard server running?");
    }
    if (!response.ok) {
      let message = response.statusText || `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body && body.error) message = body.error;
      } catch {
        /* non-JSON error body */
      }
      throw new HttpError(response.status, message);
    }
    return response.json();
  }

  function banner(key, message) {
    const stack = $("banners");
    const existing = stack.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (existing) existing.remove();
    const el = document.createElement("div");
    el.className = "banner";
    el.setAttribute("role", "alert");
    el.dataset.key = key;
    el.innerHTML = `<span>${esc(message)}</span><button type="button" aria-label="Dismiss">&times;</button>`;
    el.querySelector("button").addEventListener("click", () => el.remove());
    stack.appendChild(el);
  }

  function clearBanners() {
    $("banners").replaceChildren();
  }

  function sectionError(el, what, err) {
    el.innerHTML = `<div class="section-error">Could not load ${esc(what)}.</div>`;
    banner(what, `Could not load ${what}: ${err.message || err}`);
  }

  // ------------------------------------------------------------------ URL hash state

  function readHash() {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const int = (k) => {
      const v = Number.parseInt(params.get(k) || "", 10);
      return Number.isFinite(v) && v > 0 ? v : null;
    };
    return { project: params.get("project") || null, scan: int("scan"), finding: int("finding") };
  }

  function writeHash() {
    const params = new URLSearchParams();
    if (state.project) params.set("project", state.project);
    if (state.scan) params.set("scan", String(state.scan));
    if (state.finding) params.set("finding", String(state.finding));
    const hash = params.toString();
    const target = hash ? `#${hash}` : window.location.pathname + window.location.search;
    if (window.location.hash.replace(/^#/, "") !== hash) history.replaceState(null, "", target);
  }

  // ------------------------------------------------------------------ loading

  function setBusy(busy) {
    $("main").setAttribute("aria-busy", busy ? "true" : "false");
    const btn = $("refresh-btn");
    btn.disabled = busy;
    btn.classList.toggle("is-loading", busy);
  }

  function showEmpty(empty) {
    $("empty-state").hidden = !empty;
    $("dashboard").hidden = empty;
    $("project-select").disabled = empty;
    $("scan-select").disabled = empty;
  }

  async function run(gen, what, el, loader, render) {
    try {
      const data = await loader();
      if (gen === state.gen) render(data);
    } catch (err) {
      if (gen === state.gen) sectionError(el, what, err);
    }
  }

  async function loadAll() {
    const gen = ++state.gen;
    setBusy(true);
    clearBanners();
    try {
      let projects;
      try {
        projects = await api("/api/projects");
      } catch (err) {
        banner("projects", `Could not reach the dashboard API: ${err.message}`);
        return;
      }
      if (gen !== state.gen) return;
      state.projects = projects;
      if (!projects.length) {
        state.project = null;
        state.scan = null;
        writeHash();
        showEmpty(true);
        return;
      }
      showEmpty(false);
      if (!projects.some((p) => p.project === state.project)) {
        state.project = projects[0].project;
        state.scan = null;
      }
      renderProjectSelect();

      let scans = [];
      try {
        scans = await api("/api/scans", { project: state.project, limit: 200 });
      } catch (err) {
        banner("scans", `Could not load scans: ${err.message}`);
      }
      if (gen !== state.gen) return;
      state.scans = scans;
      if (!scans.some((s) => s.id === state.scan)) state.scan = scans.length ? scans[0].id : null;
      renderScanSelect();
      renderScanHistory();
      writeHash();

      const sel = { project: state.project, scan: state.scan };
      await Promise.all([
        run(gen, "overview", $("hero-summary"), () => api("/api/overview", sel), renderOverview),
        run(gen, "risk trend", $("trend-chart"), () => api("/api/trends", { project: state.project, last_n: 30 }), renderTrend),
        run(gen, "hotspots", $("hotspots-list"), () => api("/api/hotspots", { ...sel, limit: 8 }), renderHotspots),
        run(gen, "priorities", $("priorities-list"), () => api("/api/priorities", { ...sel, limit: 8 }), renderPriorities),
        run(gen, "recurring rules", $("recurring-body"), () => api("/api/recurring", { project: state.project, limit: 10 }), renderRecurring),
        run(gen, "remediation progress", $("progress"), () => api("/api/progress", sel), renderProgress),
        loadFindings(),
      ]);
      if (gen === state.gen && state.finding) openFinding(state.finding, { keepFocus: true });
    } finally {
      if (gen === state.gen) setBusy(false);
    }
  }

  // ------------------------------------------------------------------ selectors

  function renderProjectSelect() {
    const select = $("project-select");
    select.replaceChildren(
      ...state.projects.map((p) => new Option(`${p.project} (${num(p.scan_count)} scans)`, p.project)),
    );
    select.value = state.project;
  }

  function scanLabel(s) {
    return `#${s.id} · ${fmtDate(s.timestamp)} · ${num(s.actionable_findings)} actionable · max ${num(s.max_risk)}`;
  }

  function renderScanSelect() {
    const select = $("scan-select");
    if (!state.scans.length) {
      select.replaceChildren(new Option("No scans", ""));
      return;
    }
    select.replaceChildren(
      ...state.scans.map((s, i) => new Option(i === 0 ? `${scanLabel(s)} (latest)` : scanLabel(s), String(s.id))),
    );
    select.value = String(state.scan);
  }

  function selectScan(id) {
    if (!id || id === state.scan) return;
    state.scan = id;
    state.finding = null;
    state.explorer.offset = 0;
    closeDrawer({ silent: true });
    loadAll();
  }

  // ------------------------------------------------------------------ overview

  function deltaPill(label, delta, lowerIsBetter = true) {
    const d = num(delta);
    let tone = "tone-flat";
    if (d !== 0 && lowerIsBetter !== null) tone = (lowerIsBetter ? d < 0 : d > 0) ? "tone-good" : "tone-bad";
    return `<span class="pill ${tone}">${esc(label)} ${esc(signed(d))}</span>`;
  }

  function renderOverview(o) {
    const scan = o.latest_scan;
    const bands = o.latest_risk_bands || {};
    const deltas = o.deltas || {};
    $("hero-project").textContent = `Project · ${o.project || state.project || "default"}`;
    if (!scan) {
      $("hero-summary").textContent = "No scans stored for this project yet.";
      return;
    }
    const prev = o.previous_scan;
    const isLatest = state.scans.length && state.scans[0].id === scan.id;
    const errors = num(scan.errored_findings);
    $("hero-summary").textContent =
      `${isLatest ? "Latest scan" : `Scan #${scan.id}`} of ${scan.source_file || "an unknown source"} surfaced ` +
      `${num(scan.actionable_findings)} actionable finding(s) with a max risk of ${num(scan.max_risk)}` +
      `${errors ? `; ${errors} finding(s) could not be triaged` : ""}.`;
    $("meta-source").textContent = scan.source_file || "-";
    $("meta-timestamp").textContent = fmtDate(scan.timestamp);
    $("meta-model").textContent = scan.model || "-";
    $("meta-cost").textContent = fmtCost(scan.cost_usd);

    $("latest-actionable").textContent = num(scan.actionable_findings);
    $("latest-deltas").innerHTML = prev
      ? [
          deltaPill("Actionable", deltas.actionable_findings),
          deltaPill("High", deltas.critical_findings),
          deltaPill("Errors", deltas.errored_findings),
          deltaPill("FPs", deltas.false_positives, null),
        ].join("")
      : '<span class="pill tone-flat">First scan in this project</span>';
    $("risk-bands").innerHTML = [
      `<span class="pill risk-high">High ${esc(num(bands.high ?? bands.critical))}</span>`,
      `<span class="pill risk-medium">Medium ${esc(num(bands.medium))}</span>`,
      `<span class="pill risk-low">Low ${esc(num(bands.low))}</span>`,
      `<span class="pill risk-fp">FP ${esc(num(bands.false_positives))}</span>`,
      `<span class="pill risk-error">Errors ${esc(num(bands.errors))}</span>`,
    ].join("");

    const vs = (key) => (prev ? `${signed(deltas[key])} vs previous scan.` : "No previous scan to compare.");
    const maxRisk = num(scan.max_risk);
    $("stat-max-risk").innerHTML = `${esc(maxRisk)}<small>${maxRisk ? esc(BAND_LABEL[bandOf(maxRisk)]) : "None"}</small>`;
    $("stat-max-risk-sub").textContent = vs("max_risk");
    $("stat-critical").textContent = num(bands.high ?? bands.critical);
    $("stat-critical-sub").textContent = `Actionable, risk ${HIGH}+. ${vs("critical_findings")}`;
    $("stat-fp").textContent = num(scan.false_positives);
    $("stat-fp-sub").textContent = `Filtered out by AI triage. ${vs("false_positives")}`;
    $("stat-errors").textContent = errors;
    $("stat-errors-sub").textContent = errors
      ? "Not assessed - re-run triage for these findings."
      : "Every finding was assessed.";
    $("stat-total").textContent = num(scan.total_findings);
    $("stat-total-sub").textContent = `Scanner findings in this report. ${vs("total_findings")}`;

    renderMix(bands);
  }

  // ------------------------------------------------------------------ charts (inline SVG)

  function renderTrend(trends) {
    const el = $("trend-chart");
    if (!trends.length) {
      el.innerHTML = '<div class="empty">No trend data yet.</div>';
      return;
    }
    const W = 640;
    const H = 250;
    const L = 30;
    const R = 78;
    const T = 12;
    const B = 30;
    const iw = W - L - R;
    const ih = H - T - B;
    const n = trends.length;
    const x = (i) => (n === 1 ? L + iw / 2 : L + (i * iw) / (n - 1));
    const y = (v) => T + ih - (Math.max(0, Math.min(10, num(v))) / 10) * ih;
    const fx = (v) => v.toFixed(1);

    const parts = [];
    for (let v = 0; v <= 10; v += 2) {
      parts.push(`<line class="chart-grid-line" x1="${L}" x2="${W - R}" y1="${fx(y(v))}" y2="${fx(y(v))}"/>`);
      parts.push(`<text class="chart-label" x="${L - 8}" y="${fx(y(v) + 4)}" text-anchor="end">${v}</text>`);
    }
    parts.push(`<line class="chart-threshold t-high" x1="${L}" x2="${W - R}" y1="${fx(y(HIGH))}" y2="${fx(y(HIGH))}"/>`);
    parts.push(`<text class="chart-label" x="${W - R + 6}" y="${fx(y(HIGH) + 4)}">high ≥ ${HIGH}</text>`);
    parts.push(`<line class="chart-threshold t-med" x1="${L}" x2="${W - R}" y1="${fx(y(MEDIUM))}" y2="${fx(y(MEDIUM))}"/>`);
    parts.push(`<text class="chart-label" x="${W - R + 6}" y="${fx(y(MEDIUM) + 4)}">medium ≥ ${MEDIUM}</text>`);

    const maxPts = trends.map((t, i) => `${fx(x(i))},${fx(y(t.max_risk))}`);
    const avgPts = trends.map((t, i) => `${fx(x(i))},${fx(y(t.avg_risk ?? 0))}`);
    if (n > 1) {
      parts.push(`<path class="chart-area-max" d="M${fx(x(0))},${fx(y(0))} L${maxPts.join(" L")} L${fx(x(n - 1))},${fx(y(0))} Z"/>`);
      parts.push(`<path class="chart-line-max" d="M${maxPts.join(" L")}"/>`);
      parts.push(`<path class="chart-line-avg" d="M${avgPts.join(" L")}"/>`);
    }

    const labelEvery = Math.max(1, Math.ceil(n / 6));
    trends.forEach((t, i) => {
      const selected = t.id === state.scan;
      if (selected) {
        parts.push(`<line class="chart-selected-line" x1="${fx(x(i))}" x2="${fx(x(i))}" y1="${T}" y2="${T + ih}"/>`);
      }
      if (i % labelEvery === 0 || i === n - 1) {
        const label = fmtDate(t.timestamp, { month: "short", day: "numeric" });
        const anchor = n === 1 ? "middle" : i === 0 ? "start" : i === n - 1 ? "end" : "middle";
        parts.push(`<text class="chart-label" x="${fx(x(i))}" y="${H - 8}" text-anchor="${anchor}">${esc(label)}</text>`);
      }
      const tip =
        `Scan #${num(t.id)} · ${fmtDate(t.timestamp)}\nMax risk ${num(t.max_risk)} · ` +
        `avg ${t.avg_risk ?? "-"} · ${num(t.finding_count)} actionable` +
        ` (high ${num(t.high)}, medium ${num(t.medium)}, low ${num(t.low)})`;
      const sel = selected ? " chart-dot-selected" : "";
      parts.push(
        `<g class="chart-point" data-scan="${esc(num(t.id))}"><title>${esc(tip)}</title>` +
          `<circle class="chart-dot-avg${sel}" cx="${fx(x(i))}" cy="${fx(y(t.avg_risk ?? 0))}" r="${selected ? 5 : 3.5}"/>` +
          `<circle class="chart-dot-max${sel}" cx="${fx(x(i))}" cy="${fx(y(t.max_risk))}" r="${selected ? 6 : 4}"/>` +
          `<circle cx="${fx(x(i))}" cy="${fx(y(t.max_risk))}" r="12" fill="transparent"/></g>`,
      );
    });

    const last = trends[n - 1];
    const summary =
      `Risk trend over ${n} scan(s). Latest max risk ${num(last.max_risk)}, ` +
      `average actionable risk ${last.avg_risk ?? 0}.`;
    el.innerHTML =
      `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(summary)}" preserveAspectRatio="xMidYMid meet">` +
      parts.join("") +
      "</svg>" +
      '<ul class="legend">' +
      '<li><span class="swatch swatch-line sw-high"></span>Max risk (solid)</li>' +
      '<li><span class="swatch swatch-line sw-avg"></span>Average actionable risk (dashed)</li>' +
      "<li>Select a point to open that scan</li></ul>";
  }

  function renderMix(bands) {
    const el = $("mix-chart");
    const segments = [
      ["high", `High (${HIGH}-10)`, num(bands.high ?? bands.critical)],
      ["medium", `Medium (${MEDIUM}-${HIGH - 1})`, num(bands.medium)],
      ["low", `Low (0-${MEDIUM - 1})`, num(bands.low)],
      ["fp", "False positives", num(bands.false_positives)],
      ["error", "Triage errors (not assessed)", num(bands.errors)],
    ];
    const total = segments.reduce((acc, s) => acc + s[2], 0);
    if (!total) {
      el.innerHTML = '<div class="empty">No findings in this scan.</div>';
      return;
    }
    let offset = 0;
    const rects = segments
      .filter((s) => s[2] > 0)
      .map(([key, label, count]) => {
        const w = (count / total) * 100;
        const r = `<rect class="seg-${key}" x="${offset.toFixed(3)}" y="0" width="${w.toFixed(3)}" height="10">` +
          `<title>${esc(label)}: ${count}</title></rect>`;
        offset += w;
        return r;
      })
      .join("");
    const summary = segments.map(([, label, count]) => `${label}: ${count}`).join(", ");
    const rows = segments
      .map(([key, label, count]) => {
        const pct = Math.round((count / total) * 100);
        return `<tr><td><span class="swatch sw-${key}"></span> ${esc(label)}</td><td>${count} (${pct}%)</td></tr>`;
      })
      .join("");
    el.innerHTML =
      `<svg class="mix-svg" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="${esc(`Risk mix of ${total} findings. ${summary}`)}">` +
      '<defs><pattern id="vs-hatch" width="2" height="2" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">' +
      '<line class="hatch-line" x1="0" y1="0" x2="0" y2="2"/></pattern></defs>' +
      `${rects}</svg>` +
      `<table class="mix-table"><thead><tr><th scope="col">Bucket</th><th scope="col">Findings</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  // ------------------------------------------------------------------ progress / lists

  function renderProgress(p) {
    const el = $("progress");
    if (!p.scan_id) {
      el.innerHTML = '<div class="empty">No scans yet.</div>';
      return;
    }
    if (!p.previous_scan_id) {
      el.innerHTML =
        `<div class="empty">This is the first scan in this project, so there is nothing to compare yet. ` +
        `${num(p.new)} actionable finding(s) recorded as a baseline.</div>`;
      return;
    }
    const col = (cls, title, count, items, hint) => {
      const list = items.slice(0, 5).map((it) =>
        `<li>${riskBadge(it.risk_score)}<span><strong>${esc(it.title || it.rule_id)}</strong><br>` +
        `<span class="loc">${esc(it.file_path || "-")}</span></span></li>`,
      );
      const more = count > 5 ? `<li class="muted">+${count - 5} more</li>` : "";
      return (
        `<div class="progress-col ${cls}"><h3><span>${esc(title)}</span><strong>${esc(count)}</strong></h3>` +
        `<p class="cell-sub">${esc(hint)}</p>` +
        `<ul>${list.join("")}${more || (count ? "" : '<li class="muted">None</li>')}</ul></div>`
      );
    };
    el.innerHTML =
      `<div class="progress-grid">` +
      col("resolved", "Resolved", num(p.resolved), p.resolved_items || [], "Actionable last time, gone from this scan.") +
      col("new", "New", num(p.new), p.new_items || [], "Actionable now, absent from the previous scan.") +
      col("recurring", "Recurring", num(p.recurring), p.recurring_items || [], "Still present since the previous scan.") +
      `</div>`;
    $("progress-sub").textContent =
      `Scan #${p.scan_id} compared with scan #${p.previous_scan_id} (matched on rule, file and title).`;
  }

  function renderHotspots(spots) {
    const el = $("hotspots-list");
    if (!spots.length) {
      el.innerHTML = '<div class="empty">No actionable findings in this scan.</div>';
      return;
    }
    el.innerHTML = spots
      .map(
        (s) => `<button type="button" class="list-item" data-search="${esc(s.file_path)}">
          <div><strong class="mono">${esc(s.file_path || "(no file)")}</strong>
          <p>${esc(num(s.finding_count))} finding(s) · ${esc(num(s.high_risk_count))} high · avg ${esc(s.avg_risk ?? 0)} · total ${esc(num(s.total_risk))}</p></div>
          ${riskBadge(s.max_risk)}</button>`,
      )
      .join("");
  }

  function renderPriorities(items) {
    const el = $("priorities-list");
    if (!items.length) {
      el.innerHTML = '<div class="empty">Nothing actionable in this scan.</div>';
      return;
    }
    el.innerHTML = items
      .map(
        (f) => `<button type="button" class="list-item" data-finding="${esc(num(f.id))}">
          <div><strong>${esc(f.title || f.rule_id)}</strong>
          <p><span class="loc">${esc(location(f.file_path, f.line))}</span> · <code>${esc(f.rule_id)}</code></p>
          ${f.remediation_title ? `<p>Fix: ${esc(f.remediation_title)}</p>` : ""}</div>
          ${riskBadge(f.risk_score)}</button>`,
      )
      .join("");
  }

  function renderRecurring(rows) {
    const body = $("recurring-body");
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="4" class="empty-cell"><div class="empty">No recurring rules yet.</div></td></tr>';
      return;
    }
    body.innerHTML = rows
      .map(
        (r) => `<tr class="clickable" tabindex="0" data-search="${esc(r.rule_id)}">
          <td><code>${esc(r.rule_id)}</code><div class="cell-sub">${esc(r.title)}</div></td>
          <td>${esc(num(r.occurrences))}</td><td>${riskBadge(r.max_risk)}</td><td>${esc(num(r.scan_count))}</td></tr>`,
      )
      .join("");
  }

  function renderScanHistory() {
    const body = $("scans-body");
    if (!state.scans.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty-cell"><div class="empty">No scans for this project.</div></td></tr>';
      return;
    }
    body.innerHTML = state.scans
      .slice(0, 25)
      .map(
        (s) => `<tr class="clickable${s.id === state.scan ? " is-selected" : ""}" tabindex="0" data-scan="${esc(num(s.id))}"
            ${s.id === state.scan ? 'aria-current="true"' : ""}>
          <td>${esc(fmtDate(s.timestamp))}<div class="cell-sub">#${esc(num(s.id))}</div></td>
          <td class="loc">${esc(s.source_file)}</td>
          <td>${esc(num(s.actionable_findings))} / ${esc(num(s.total_findings))}</td>
          <td>${riskBadge(s.max_risk)}</td>
          <td>${esc(num(s.false_positives))} / ${esc(num(s.errored_findings))}</td></tr>`,
      )
      .join("");
  }

  // ------------------------------------------------------------------ findings explorer

  function emptyRow(html, cls = "empty") {
    return `<tr><td colspan="4" class="empty-cell"><div class="${cls}">${html}</div></td></tr>`;
  }

  async function loadFindings() {
    const my = ++state.fgen;
    const body = $("findings-body");
    if (!state.scan) {
      body.innerHTML = emptyRow("No scan selected.");
      renderPager(0, 0);
      return;
    }
    const ex = state.explorer;
    body.setAttribute("aria-busy", "true");
    if (!body.children.length) body.innerHTML = emptyRow("Loading findings…", "loading");
    try {
      const data = await api(`/api/scans/${encodeURIComponent(state.scan)}/findings`, {
        q: ex.q,
        band: ex.band,
        status: ex.status,
        sort: ex.sort,
        limit: ex.limit,
        offset: ex.offset,
      });
      if (my !== state.fgen) return;
      if (data.total > 0 && ex.offset >= data.total) {
        ex.offset = Math.max(0, Math.floor((data.total - 1) / ex.limit) * ex.limit);
        loadFindings();
        return;
      }
      renderFindings(data);
    } catch (err) {
      if (my !== state.fgen) return;
      body.innerHTML = emptyRow(`Could not load findings: ${esc(err.message)}`, "section-error");
      banner("findings", `Could not load findings: ${err.message}`);
      renderPager(0, 0);
    } finally {
      if (my === state.fgen) body.removeAttribute("aria-busy");
    }
  }

  function renderFindings(data) {
    const body = $("findings-body");
    const ex = state.explorer;
    if (!data.items.length) {
      const filtered = ex.q || ex.band || ex.status !== "all";
      body.innerHTML = emptyRow(filtered ? "No findings match these filters." : "This scan has no findings.");
    } else {
      body.innerHTML = data.items
        .map((f) => {
          const cls = ["clickable"];
          if (f.status === "error") cls.push("is-error");
          if (f.id === state.finding) cls.push("is-selected");
          const ids = [f.cwe, f.cve].filter(Boolean).map(esc).join(" · ");
          return `<tr class="${cls.join(" ")}" tabindex="0" data-finding="${esc(num(f.id))}"
              aria-label="${esc(`${f.title || f.rule_id}, ${STATUS_LABEL[f.status] || ""}, risk ${num(f.risk_score)}`)}">
            <td>${riskBadge(f.risk_score, f.status)}</td>
            <td><div class="cell-title">${esc(f.title || f.rule_id)}</div>
              <div class="cell-sub"><code>${esc(f.rule_id)}</code>${f.severity ? ` · scanner: ${esc(f.severity)}` : ""}${ids ? ` · ${ids}` : ""}</div></td>
            <td class="loc">${esc(location(f.file_path, f.line))}</td>
            <td>${statusBadge(f.status)}${f.confidence !== null && f.confidence !== undefined ? `<div class="cell-sub">conf. ${esc(num(f.confidence))}/10</div>` : ""}</td>
          </tr>`;
        })
        .join("");
    }
    renderPager(data.total, data.items.length);
  }

  function renderPager(total, shown) {
    const ex = state.explorer;
    $("pager-info").textContent = total
      ? `${ex.offset + 1}–${ex.offset + shown} of ${total} finding(s)`
      : "0 findings";
    $("pager-prev").disabled = ex.offset <= 0;
    $("pager-next").disabled = ex.offset + ex.limit >= total;
  }

  function applySearch(term) {
    $("f-q").value = term;
    state.explorer.q = term;
    state.explorer.offset = 0;
    loadFindings();
    $("explorer").scrollIntoView({ behavior: "smooth", block: "start" });
    $("f-q").focus({ preventScroll: true });
  }

  // ------------------------------------------------------------------ finding drawer

  function cweLink(cwe) {
    const m = /^CWE-(\d{1,6})$/i.exec(String(cwe || "").trim());
    return m ? linkOrText(`https://cwe.mitre.org/data/definitions/${m[1]}.html`, cwe) : esc(cwe);
  }

  function cveLink(cve) {
    const m = /^CVE-\d{4}-\d{4,8}$/i.exec(String(cve || "").trim());
    return m ? linkOrText(`https://nvd.nist.gov/vuln/detail/${m[0].toUpperCase()}`, cve) : esc(cve);
  }

  function textSection(title, text, fallback = "None recorded.") {
    const body = text ? `<p>${esc(text)}</p>` : `<p class="muted">${esc(fallback)}</p>`;
    return `<section><h3>${esc(title)}</h3>${body}</section>`;
  }

  function renderDrawer(f) {
    $("drawer-title").textContent = f.title || f.rule_id || "Finding";
    const facts = [
      ["Risk score", f.status === "error" ? "Not assessed" : `${num(f.risk_score)}/10 · ${f.status === "fp" ? "false positive" : BAND_LABEL[bandOf(f.risk_score)]}`],
      ["Confidence", f.confidence === null || f.confidence === undefined ? "Not reported" : `${num(f.confidence)}/10`],
      ["Scanner severity", f.severity || "-"],
      ["Source", f.source_format || "-"],
    ].map(([k, v]) => `<div class="fact"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`);
    facts.push(`<div class="fact"><dt>Rule</dt><dd><code>${esc(f.rule_id || "-")}</code></dd></div>`);
    if (f.cwe) facts.push(`<div class="fact"><dt>CWE</dt><dd>${cweLink(f.cwe)}</dd></div>`);
    if (f.cve) facts.push(`<div class="fact"><dt>CVE</dt><dd>${cveLink(f.cve)}</dd></div>`);

    const parts = [];
    parts.push(`<div class="pill-row">${riskBadge(f.risk_score, f.status)} ${statusBadge(f.status)}</div>`);
    if (f.status === "error") {
      parts.push(
        `<div class="error-box" role="note"><strong>Triage failed - this finding was not assessed.</strong>` +
          ` It is counted neither as actionable nor as a false positive. Re-run triage to score it.` +
          `${f.error ? `<p class="mono">${esc(f.error)}</p>` : ""}</div>`,
      );
    }
    parts.push(
      `<section><h3>Location</h3><p class="loc">${esc(location(f.file_path, f.line, f.end_line))}</p>` +
        `<p class="cell-sub">Scan #${esc(num(f.scan_id))} · ${esc(f.project || "")} · ${esc(fmtDate(f.scan_timestamp))}` +
        ` · finding id <code>${esc(f.finding_id)}</code></p></section>`,
    );
    parts.push(`<dl class="facts">${facts.join("")}</dl>`);
    if (f.message || f.description) {
      const msg = [f.message, f.description && f.description !== f.message ? f.description : ""].filter(Boolean).join("\n\n");
      parts.push(textSection("Scanner message", msg));
    }
    if (f.status !== "error") {
      parts.push(textSection("AI reasoning", f.reasoning));
      parts.push(textSection("Exploitability", f.exploitability_notes));
    }
    if (f.snippet) parts.push(`<section><h3>Code (from scanner)</h3><pre><code>${esc(f.snippet)}</code></pre></section>`);

    const r = f.remediation;
    if (r) {
      const steps = Array.isArray(r.steps) && r.steps.length
        ? `<ol>${r.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>`
        : '<p class="muted">No steps recorded.</p>';
      const links = (Array.isArray(r.reference_links) ? r.reference_links : [])
        .map((u) => {
          const href = safeUrl(u);
          return href
            ? `<li><a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></li>`
            : `<li class="muted">${esc(u)} (not a web link)</li>`;
        })
        .join("");
      parts.push(
        `<section><h3>Remediation</h3>${r.title ? `<p><strong>${esc(r.title)}</strong></p>` : ""}` +
          `${r.business_impact ? `<p class="muted">${esc(r.business_impact)}</p>` : ""}</section>`,
      );
      parts.push(`<section><h3>Steps</h3>${steps}</section>`);
      if (r.code_snippet) parts.push(`<section><h3>Suggested fix</h3><pre><code>${esc(r.code_snippet)}</code></pre></section>`);
      if (links) parts.push(`<section><h3>References</h3><ul class="links">${links}</ul></section>`);
    } else if (f.status === "actionable") {
      parts.push(textSection("Remediation", "", "No remediation card stored for this finding."));
    }
    $("drawer-body").innerHTML = parts.join("");
  }

  function highlightRow() {
    document.querySelectorAll("#findings-body tr[data-finding]").forEach((tr) => {
      tr.classList.toggle("is-selected", Number(tr.dataset.finding) === state.finding);
    });
  }

  async function openFinding(id, { keepFocus = false } = {}) {
    const drawer = $("drawer");
    if (drawer.hidden && !keepFocus) state.lastFocus = document.activeElement;
    state.finding = id;
    writeHash();
    highlightRow();
    drawer.hidden = false;
    $("drawer-backdrop").hidden = false;
    document.body.style.overflow = "hidden";
    $("drawer-title").textContent = "Loading finding…";
    $("drawer-body").innerHTML = '<div class="loading">Loading…</div>';
    drawer.focus();
    try {
      const f = await api(`/api/findings/${encodeURIComponent(id)}`);
      if (state.finding !== id) return;
      renderDrawer(f);
    } catch (err) {
      if (state.finding !== id) return;
      $("drawer-title").textContent = "Finding unavailable";
      const msg = err.status === 404 ? "This finding no longer exists (its scan may have been deleted)." : err.message;
      $("drawer-body").innerHTML = `<div class="section-error">${esc(msg)}</div>`;
    }
  }

  function closeDrawer({ silent = false } = {}) {
    const drawer = $("drawer");
    if (drawer.hidden) return;
    drawer.hidden = true;
    $("drawer-backdrop").hidden = true;
    document.body.style.overflow = "";
    if (!silent) {
      state.finding = null;
      writeHash();
      highlightRow();
      const back = state.lastFocus;
      if (back && document.contains(back)) back.focus();
    }
  }

  function trapFocus(event) {
    if (event.key !== "Tab") return;
    const drawer = $("drawer");
    const focusable = [...drawer.querySelectorAll("a[href], button:not([disabled]), [tabindex]:not([tabindex='-1'])")];
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === drawer)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  // ------------------------------------------------------------------ events

  function activate(target) {
    const findingEl = target.closest("[data-finding]");
    if (findingEl) return openFinding(Number(findingEl.dataset.finding));
    const scanEl = target.closest("[data-scan]");
    if (scanEl) return selectScan(Number(scanEl.dataset.scan));
    const searchEl = target.closest("[data-search]");
    if (searchEl) return applySearch(searchEl.dataset.search);
    return undefined;
  }

  function bind() {
    $("project-select").addEventListener("change", (e) => {
      state.project = e.target.value;
      state.scan = null;
      state.finding = null;
      state.explorer.offset = 0;
      closeDrawer({ silent: true });
      loadAll();
    });
    $("scan-select").addEventListener("change", (e) => selectScan(Number(e.target.value)));
    $("refresh-btn").addEventListener("click", () => loadAll());

    const ex = state.explorer;
    $("explorer-form").addEventListener("submit", (e) => e.preventDefault());
    const onSearch = debounce(() => {
      ex.q = $("f-q").value.trim();
      ex.offset = 0;
      loadFindings();
    }, 250);
    $("f-q").addEventListener("input", onSearch);
    for (const [id, key] of [["f-status", "status"], ["f-band", "band"], ["f-sort", "sort"]]) {
      $(id).addEventListener("change", (e) => {
        ex[key] = e.target.value;
        ex.offset = 0;
        loadFindings();
      });
    }
    $("pager-prev").addEventListener("click", () => {
      ex.offset = Math.max(0, ex.offset - ex.limit);
      loadFindings();
    });
    $("pager-next").addEventListener("click", () => {
      ex.offset += ex.limit;
      loadFindings();
    });

    $("main").addEventListener("click", (e) => {
      if (e.target.closest("a")) return;
      activate(e.target);
    });
    $("main").addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr[tabindex]")) {
        e.preventDefault();
        activate(e.target);
      }
    });

    $("drawer-close").addEventListener("click", () => closeDrawer());
    $("drawer-backdrop").addEventListener("click", () => closeDrawer());
    $("drawer").addEventListener("keydown", trapFocus);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("drawer").hidden) closeDrawer();
    });

    window.addEventListener("hashchange", () => {
      const h = readHash();
      if ((h.project && h.project !== state.project) || (h.scan && h.scan !== state.scan)) {
        Object.assign(state, { project: h.project || state.project, scan: h.scan, finding: h.finding });
        closeDrawer({ silent: true });
        loadAll();
      } else if (h.finding && h.finding !== state.finding) {
        openFinding(h.finding);
      } else if (!h.finding && state.finding) {
        closeDrawer();
      }
    });
  }

  function init() {
    Object.assign(state, readHash());
    bind();
    loadAll();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
