"use strict";

const STEPS = [
  ["ingest",   "Reading input"],
  ["detect",   "Scanning for red flags"],
  ["context",  "Understanding the message"],
  ["classify", "Matching scam patterns"],
  ["research", "Live-checking links & numbers"],
  ["verdict",  "Weighing the evidence"],
  ["action",   "Preparing your next steps"],
];

const RISK = {
  critical: { color: "#ff5a5f", label: "Critical — almost certainly a scam" },
  high:     { color: "#ff8c42", label: "High — likely a scam" },
  medium:   { color: "#ffcf4d", label: "Suspicious — verify before acting" },
  low:      { color: "#52c07a", label: "Low — probably legitimate" },
  info:     { color: "#7f8da3", label: "No strong scam signals found" },
};

const $ = (sel) => document.querySelector(sel);
let pickedFile = null;

// tiny DOM helper — text goes in as textContent so scam strings can't inject markup
function el(tag, opts = {}, ...kids) {
  const n = document.createElement(tag);
  if (opts.class) n.className = opts.class;
  if (opts.text != null) n.textContent = opts.text;
  if (opts.html != null) n.innerHTML = opts.html;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) n.setAttribute(k, v);
  for (const k of kids) if (k) n.append(k);
  return n;
}

// ---------- boot ----------
async function boot() {
  try {
    const h = await (await fetch("/api/health")).json();
    const caps = $("#caps");
    const c = h.capabilities || {};
    caps.append(
      pill(!!c.reasoning_model, "Reasoning", c.reasoning_model || "no model key"),
      pill(!!c.vision_model, "Vision", c.vision_model || "off"),
      pill(!!c.live_research, "Live research", c.live_research ? "Tavily" : "off (no key)"),
    );
    if (h.note) caps.append(el("span", { class: "pill off", text: h.note }));
  } catch (e) { /* health is best-effort */ }

  try {
    const samples = await (await fetch("/api/samples")).json();
    const box = $("#samples");
    for (const s of samples) {
      const chip = el("button", { class: "chip", text: s.label });
      chip.onclick = () => loadSample(s.id);
      box.append(chip);
    }
  } catch (e) { /* ignore */ }

  try {
    const adv = await (await fetch("/api/adversarial")).json();
    const box = $("#adversarial");
    for (const s of adv) {
      const chip = el("button", { class: "chip chip-adv", text: s.label });
      chip.onclick = () => loadSampleAndRun(s.id);
      box.append(chip);
    }
  } catch (e) { /* ignore */ }
}

function pill(on, name, val) {
  return el("span", { class: "pill " + (on ? "on" : "off"),
    html: `<b>${name}:</b> ${escapeHtml(val)}` });
}

async function loadSample(id) {
  const s = await (await fetch("/api/samples/" + id)).json();
  $("#input").value = s.text;
  $("#region").value = s.region_hint || "";
  clearFile();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Challenge mode: load an adversarial example and run it immediately, so the
// robustness (a look-alike caught, an injection treated as data) is one click away.
async function loadSampleAndRun(id) {
  await loadSample(id);
  run();
}

// ---------- file ----------
$("#file").addEventListener("change", (e) => {
  const f = e.target.files[0];
  if (!f) return;
  pickedFile = f;
  const t = $("#thumb");
  t.innerHTML = "";
  const img = el("img");
  img.src = URL.createObjectURL(f);
  const rm = el("button", { class: "chip", text: "remove" });
  rm.onclick = clearFile;
  t.append(img, el("span", { text: f.name }), rm);
  t.style.display = "flex";
});

function clearFile() {
  pickedFile = null;
  $("#file").value = "";
  $("#thumb").style.display = "none";
  $("#thumb").innerHTML = "";
}

// ---------- run ----------
$("#go").addEventListener("click", run);

function looksLikeUrl(s) {
  return /^https?:\/\/\S+$/i.test(s.trim()) || /^www\.\S+$/i.test(s.trim());
}

async function run() {
  const text = $("#input").value.trim();
  if (!text && !pickedFile) { flash("Paste a message or add a screenshot first."); return; }

  const fd = new FormData();
  if (pickedFile) fd.append("images", pickedFile);
  if (text && looksLikeUrl(text) && !pickedFile) fd.append("url", text);
  else if (text) fd.append("text", text);
  const region = $("#region").value;
  if (region) fd.append("region_hint", region);

  setBusy(true);
  renderSteps();
  $("#result").className = "result";
  $("#result").innerHTML = "";
  $("#errBanner").style.display = "none";

  try {
    const resp = await fetch("/api/analyze/stream", { method: "POST", body: fd });
    if (!resp.ok || !resp.body) throw new Error("Server error " + resp.status);
    await consume(resp.body);
  } catch (e) {
    flash("Something went wrong: " + e.message);
  } finally {
    setBusy(false);
  }
}

async function consume(body) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const line = block.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line.slice(5).trim()); } catch { continue; }
      handle(msg);
    }
  }
}

function handle(msg) {
  if (msg.type === "result") { renderResult(msg.result); return; }
  if (msg.type === "step") {
    if (msg.step === "error") { flash(msg.message); return; }
    markStep(msg.step, msg.status, msg.message);
  }
}

// ---------- steps UI ----------
function renderSteps() {
  const box = $("#steps");
  box.className = "steps show";
  box.innerHTML = "";
  for (const [id, label] of STEPS) {
    box.append(el("div", { class: "step", attrs: { "data-step": id } },
      el("span", { class: "dot" }),
      el("span", { class: "s-label", text: label }),
    ));
  }
}

function markStep(step, status, message) {
  const node = document.querySelector(`.step[data-step="${step}"]`);
  if (!node) return;
  node.classList.remove("active", "done", "err");
  const label = node.querySelector(".s-label");
  const old = node.querySelector(".spin"); if (old) old.remove();
  if (status === "started") {
    node.classList.add("active");
    node.append(el("span", { class: "spin" }));
  } else if (status === "done") {
    node.classList.add("done");
    if (message) label.textContent = message;
    // mark everything above as done too, in case an event was coalesced
  } else if (status === "skipped") {
    node.classList.add("done");
    if (message) label.textContent = message;
  } else if (status === "error") {
    node.classList.add("err");
    if (message) label.textContent = message;
  }
}

// ---------- result UI ----------
function renderResult(r) {
  const root = $("#result");
  root.innerHTML = "";
  root.className = "result show";

  const v = r.verdict;
  const rc = (RISK[v.risk_level] || RISK.info).color;

  // verdict banner + gauge
  const banner = el("div", { class: "verdict" });
  banner.style.setProperty("--rc", rc);
  banner.style.borderColor = rc;
  banner.append(gauge(v.score, rc));
  banner.append(el("div", { class: "vtext" },
    el("div", { class: "level", text: (RISK[v.risk_level] || RISK.info).label }),
    el("div", { class: "headline", text: v.headline }),
  ));
  root.append(banner);

  // evidence check — the trust centerpiece. Before we show a single reason, we
  // show our working: how many findings the model put forward, how many the
  // evidence could actually back, and any it couldn't. This is the thing that
  // separates Telltale from "ask an LLM and hope."
  if (r.evidence_audit && r.evidence_audit.proposed > 0) {
    root.append(evidenceCheck(r.evidence_audit, r.rejected_claims || []));
  }

  // tells
  if (v.tells && v.tells.length) {
    const sec = section("Why — the tells");
    for (const t of v.tells) {
      const card = el("div", { class: "tell" });
      card.style.setProperty("--rc", rc);
      card.append(el("div", { class: "t-title", text: t.title }));
      card.append(el("div", { class: "t-exp", text: t.explanation }));
      if (t.evidence_type === "quote" && t.quote)
        card.append(el("div", { class: "quote", text: "“" + t.quote + "”" }));
      const badgeText = t.evidence_type === "source" ? "verified online"
        : t.evidence_type === "signal" ? "detected signal" : "from the message";
      card.append(el("div", { class: "badge", text: badgeText }));
      sec.append(card);
    }
    root.append(sec);
  }

  // reasoning
  if (v.reasoning) {
    const sec = section("The read");
    sec.append(el("div", { class: "how", text: v.reasoning }));
    root.append(sec);
  }

  // how the con works
  if (r.archetype && r.archetype.archetype_id !== "none" && r.archetype_how) {
    const sec = section("How this con usually works");
    const how = el("div", { class: "how" },
      el("div", { class: "name", text: r.archetype.name }),
      el("div", { text: r.archetype_how }),
    );
    if (r.archetype_refs && r.archetype_refs.length) {
      const refs = el("div", { class: "refs", html: "Basis: " +
        r.archetype_refs.map((x) => `<a href="${escapeAttr(x.url)}" target="_blank" rel="noopener">${escapeHtml(x.name)}</a>`).join(" · ") });
      how.append(refs);
    }
    sec.append(how);
    root.append(sec);
  }

  // live sources
  if (r.sources && r.sources.length) {
    const sec = section("Live research");
    for (const s of r.sources) {
      sec.append(el("div", { class: "source" },
        el("div", { html: `<a href="${escapeAttr(s.url)}" target="_blank" rel="noopener">${escapeHtml(s.title)}</a>` }),
        el("div", { class: "s-snip", text: s.snippet }),
      ));
    }
    root.append(sec);
  }

  // action plan
  const ap = r.action_plan || {};
  if ((ap.do_now && ap.do_now.length) || (ap.do_not && ap.do_not.length)) {
    const sec = section("What to do");
    const cols = el("div", { class: "cols" });
    if (ap.do_now && ap.do_now.length) {
      const box = el("div", { class: "box do" }, el("h4", { text: "Do now" }));
      const ul = el("ul");
      for (const s of ap.do_now)
        ul.append(el("li", {}, el("span", { text: s.step + " " }),
          el("span", { class: "why", text: s.why ? "— " + s.why : "" })));
      box.append(ul); cols.append(box);
    }
    if (ap.do_not && ap.do_not.length) {
      const box = el("div", { class: "box dont" }, el("h4", { text: "Don’t" }));
      const ul = el("ul");
      for (const s of ap.do_not) ul.append(el("li", { text: s }));
      box.append(ul); cols.append(box);
    }
    sec.append(cols);
    root.append(sec);
  }

  // what's not proven + what would change the verdict — the honest counterweight
  // to the tells, so the verdict never reads as more certain than it is
  const notProven = r.not_proven || [];
  if (notProven.length || (ap.how_to_verify && ap.how_to_verify.length)) {
    const sec = section("What's not proven — and what would change the verdict");
    const cols = el("div", { class: "cols" });
    if (notProven.length) {
      const box = el("div", { class: "box notproven" }, el("h4", { text: "Telltale can’t confirm" }));
      const ul = el("ul");
      for (const s of notProven) ul.append(el("li", { text: s }));
      box.append(ul); cols.append(box);
    }
    if (ap.how_to_verify && ap.how_to_verify.length) {
      const box = el("div", { class: "box wouldchange" }, el("h4", { text: "What would settle it" }));
      const ul = el("ul");
      for (const s of ap.how_to_verify) ul.append(el("li", { text: s }));
      box.append(ul); cols.append(box);
    }
    sec.append(cols);
    root.append(sec);
  }

  if (ap.report_to && ap.report_to.length) {
    const sec = section("Where to report");
    for (const c of ap.report_to) {
      const meta = [];
      if (c.phone) meta.push(`☎ ${escapeHtml(c.phone)}`);
      if (c.url) meta.push(`<a href="${escapeAttr(c.url)}" target="_blank" rel="noopener">${escapeHtml(c.url)}</a>`);
      const card = el("div", { class: "report" },
        el("div", { class: "r-name", text: `${c.name}${c.region && c.region !== "Global" ? " · " + c.region : ""}` }));
      if (meta.length) card.append(el("div", { class: "r-meta", html: meta.join(" &nbsp; ") }));
      if (c.note) card.append(el("div", { class: "r-note", text: c.note }));
      sec.append(card);
    }
    root.append(sec);
  }

  // safe reply
  if (ap.safe_reply) {
    const sec = section("A safe reply you could send");
    const wrap = el("div", { class: "reply" });
    const ta = el("textarea"); ta.value = ap.safe_reply; ta.readOnly = true;
    const btn = el("button", { class: "btn copy", text: "Copy" });
    btn.onclick = () => { navigator.clipboard.writeText(ap.safe_reply); btn.textContent = "Copied"; setTimeout(() => btn.textContent = "Copy", 1500); };
    wrap.append(ta, btn);
    sec.append(wrap);
    root.append(sec);
  }

  // entities
  const en = r.entities || {};
  const entChips = [];
  const push = (label, arr) => { for (const x of (arr || [])) entChips.push([label, x]); };
  push("link", en.domains); push("email", en.emails); push("phone", en.phones);
  push("UPI", en.upi_ids); push("wallet", en.crypto_addresses); push("amount", en.amounts);
  if (entChips.length) {
    const sec = section("What we picked out");
    const box = el("div", { class: "entities" });
    for (const [lbl, val] of entChips)
      box.append(el("span", { class: "entity", html: `<b>${lbl}</b>${escapeHtml(val)}` }));
    sec.append(box);
    root.append(sec);
  }

  // coverage + disclaimer
  if (r.coverage_notes && r.coverage_notes.length) {
    const n = el("div", { class: "notes" }, el("div", { text: "Notes on this analysis:" }));
    const ul = el("ul");
    for (const c of r.coverage_notes) ul.append(el("li", { text: c }));
    n.append(ul);
    root.append(n);
  }
  root.append(el("div", { class: "disclaimer", text: r.disclaimer || "" }));

  root.scrollIntoView({ behavior: "smooth", block: "start" });
}

// The evidence-check panel: proposed vs. backed vs. rejected, and the rejected
// claims spelled out with the reason each one failed. It renders in every mode —
// in deterministic mode "proposed" equals "backed" because the detectors only
// ever put forward what they can prove.
function evidenceCheck(audit, rejected) {
  const sec = section("Evidence check");
  sec.classList.add("evcheck");

  sec.append(el("div", { class: "ev-lead", text:
    "Nothing reaches you on the model’s word alone. Every finding has to map to a "
    + "detected signal, a live source, or a direct quote — here’s how this analysis held up." }));

  const stats = el("div", { class: "ev-stats" });
  stats.append(
    evStat(audit.proposed, "proposed", "neutral"),
    evStat(audit.kept, "backed by evidence", "ok"),
    evStat(audit.rejected, "rejected", audit.rejected > 0 ? "bad" : "muted"),
  );
  sec.append(stats);

  if (rejected.length) {
    const box = el("div", { class: "ev-rejects" });
    box.append(el("div", { class: "ev-rejects-h", text:
      "The reasoning model proposed these — the evidence layer couldn’t back them, so they were dropped:" }));
    for (const claim of rejected) {
      const card = el("div", { class: "ev-claim" });
      card.append(el("div", { class: "ev-claim-src", text: "Nemotron proposed" }));
      card.append(el("div", { class: "ev-claim-top" },
        el("span", { class: "ev-claim-title", text: claim.title || "Untitled claim" }),
        el("span", { class: "ev-claim-badge", text: "✗ rejected" }),
      ));
      card.append(el("div", { class: "ev-claim-reason", text: "Reason: " + sentence(claim.reason) }));
      box.append(card);
    }
    sec.append(box);
  } else {
    sec.append(el("div", { class: "ev-clean", text:
      "Every finding the model proposed was backed by evidence — nothing had to be dropped." }));
  }
  return sec;
}

function evStat(n, label, kind) {
  return el("div", { class: "ev-stat " + kind },
    el("div", { class: "ev-num", text: String(n) }),
    el("div", { class: "ev-lbl", text: label }),
  );
}

function sentence(s) {
  s = String(s || "").trim();
  if (!s) return "";
  s = s[0].toUpperCase() + s.slice(1);
  return /[.!?]$/.test(s) ? s : s + ".";
}

function gauge(score, color) {
  const r = 40, c = 2 * Math.PI * r, off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  const svg = `
    <svg viewBox="0 0 92 92" class="g">
      <circle cx="46" cy="46" r="${r}" fill="none" stroke="#22304a" stroke-width="8"/>
      <circle cx="46" cy="46" r="${r}" fill="none" stroke="${color}" stroke-width="8"
        stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"
        transform="rotate(-90 46 46)"/>
    </svg>`;
  const wrap = el("div", { class: "gauge", html: svg });
  wrap.append(el("div", { class: "num", text: String(score) }));
  return wrap;
}

function section(title) {
  return el("div", { class: "section" }, el("h3", { text: title }));
}

// ---------- utils ----------
function setBusy(b) {
  const btn = $("#go");
  btn.disabled = b;
  btn.textContent = b ? "Checking…" : "Check it";
}
function flash(m) {
  const b = $("#errBanner");
  b.textContent = m; b.style.display = "block";
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function escapeAttr(s) { return escapeHtml(s); }

boot();
