"use strict";

const STEPS = [
  ["ingest", "Reading input"],
  ["detect", "Scanning for red flags"],
  ["context", "Understanding the message"],
  ["classify", "Matching scam patterns"],
  ["research", "Live-checking links and numbers"],
  ["verdict", "Weighing the evidence"],
  ["action", "Preparing your next steps"],
];

const STAGE_NAMES = {
  vision: "Read screenshot",
  context: "Understand message",
  classify: "Match pattern",
  research: "Live search",
  verdict: "Weigh evidence",
  second_opinion: "Second opinion",
  action: "Next steps",
};

const RISK = {
  critical: { color: "#ff5a5f", label: "Critical, almost certainly a scam" },
  high: { color: "#ff8c42", label: "High, likely a scam" },
  medium: { color: "#ffcf4d", label: "Suspicious, verify before acting" },
  low: { color: "#52c07a", label: "Low, probably legitimate" },
  info: { color: "#7f8da3", label: "No strong scam signals found" },
};

const $ = (sel) => document.querySelector(sel);
let pickedFile = null;

// Builds elements with textContent only. Message text, model output and search results are
// untrusted, so none of it is ever parsed as HTML.
function el(tag, opts = {}, ...kids) {
  const n = document.createElement(tag);
  if (opts.class) n.className = opts.class;
  if (opts.text != null) n.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) n.setAttribute(k, v);
  for (const k of kids) if (k != null && k !== "") n.append(k);
  return n;
}

// Only http(s) links become clickable; anything else (javascript:, data:) is shown as text.
function link(url, text) {
  let href = null;
  try {
    const u = new URL(url, location.href);
    if (u.protocol === "https:" || u.protocol === "http:") href = u.href;
  } catch {
    /* not a URL */
  }
  if (!href) return el("span", { text: text || String(url) });
  return el("a", { text: text || href, attrs: { href, target: "_blank", rel: "noopener noreferrer" } });
}

function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// ---------- boot ----------
async function boot() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

  try {
    const h = await (await fetch("/api/health")).json();
    const c = h.capabilities || {};
    $("#caps").append(
      pill(!!c.reasoning_model, "Reasoning", c.reasoning_model || "no model key"),
      pill(!!c.vision_model, "Vision", c.vision_model || "off"),
      pill(!!c.live_research, "Live research", c.live_research ? "Tavily" : "off (no key)"),
    );
    if (h.note) $("#caps").append(el("span", { class: "pill off", text: h.note }));
  } catch {
    /* health is best-effort */
  }

  await chips("/api/samples", "#samples", "chip", (s) => loadSample(s.id));
  await chips("/api/adversarial", "#adversarial", "chip chip-adv", (s) => loadSampleAndRun(s.id));

  // Android share sheet: an installed Telltale receives ?text=&url=&title=.
  const p = new URLSearchParams(location.search);
  const shared = ["title", "text", "url"].map((k) => p.get(k)).filter(Boolean).join("\n").trim();
  if (shared) {
    $("#input").value = shared;
    history.replaceState(null, "", "/");
    run();
  }
}

async function chips(endpoint, target, cls, onClick) {
  try {
    for (const s of await (await fetch(endpoint)).json()) {
      const chip = el("button", { class: cls, text: s.label });
      chip.onclick = () => onClick(s);
      $(target).append(chip);
    }
  } catch {
    /* examples are optional */
  }
}

function pill(on, name, val) {
  return el("span", { class: "pill " + (on ? "on" : "off") }, el("b", { text: name }), " " + val);
}

async function loadSample(id) {
  const r = await fetch("/api/samples/" + encodeURIComponent(id));
  if (!r.ok) return;
  const s = await r.json();
  $("#input").value = s.text;
  $("#region").value = s.region_hint || "";
  clearFile();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

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
  t.replaceChildren();
  const img = el("img", { attrs: { alt: "Screenshot preview" } });
  img.src = URL.createObjectURL(f);
  const rm = el("button", { class: "chip", text: "Remove" });
  rm.onclick = clearFile;
  t.append(img, el("span", { text: f.name }), rm);
  t.style.display = "flex";
});

function clearFile() {
  pickedFile = null;
  $("#file").value = "";
  $("#thumb").style.display = "none";
  $("#thumb").replaceChildren();
}

// ---------- run ----------
$("#go").addEventListener("click", run);

function looksLikeUrl(s) {
  return /^https?:\/\/\S+$/i.test(s.trim()) || /^www\.\S+$/i.test(s.trim());
}

async function run() {
  const text = $("#input").value.trim();
  if (!text && !pickedFile) {
    flash("Paste a message or add a screenshot first.");
    return;
  }
  const fd = new FormData();
  if (pickedFile) fd.append("images", pickedFile);
  if (text && looksLikeUrl(text) && !pickedFile) fd.append("url", text);
  else if (text) fd.append("text", text);
  const region = $("#region").value;
  if (region) fd.append("region_hint", region);

  setBusy(true);
  renderSteps();
  $("#result").className = "result";
  $("#result").replaceChildren();
  $("#errBanner").style.display = "none";

  try {
    const resp = await fetch("/api/analyze/stream", { method: "POST", body: fd });
    if (!resp.ok || !resp.body) {
      let msg = `The server returned ${resp.status}.`;
      try {
        const j = await resp.json();
        msg = j.error || j.detail || msg;
      } catch {
        /* not JSON */
      }
      throw new Error(msg);
    }
    await consume(resp.body);
  } catch (e) {
    flash(e.message);
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
      try {
        msg = JSON.parse(line.slice(5).trim());
      } catch {
        continue;
      }
      handle(msg);
    }
  }
}

function handle(msg) {
  if (msg.type === "result") return renderResult(msg.result);
  if (msg.type !== "step") return;
  if (msg.step === "error") return flash(msg.message);
  markStep(msg.step, msg.status, msg.message);
}

// ---------- steps ----------
function renderSteps() {
  const box = $("#steps");
  box.className = "steps show";
  box.replaceChildren(
    ...STEPS.map(([id, label]) =>
      el("div", { class: "step", attrs: { "data-step": id } }, el("span", { class: "dot" }), el("span", { class: "s-label", text: label })),
    ),
  );
}

function markStep(step, status, message) {
  const node = document.querySelector(`.step[data-step="${step}"]`);
  if (!node) return;
  node.classList.remove("active", "done", "err");
  node.querySelector(".spin")?.remove();
  const label = node.querySelector(".s-label");
  if (status === "started") {
    node.classList.add("active");
    node.append(el("span", { class: "spin" }));
    if (message) label.textContent = message;
  } else {
    node.classList.add(status === "error" ? "err" : "done");
    if (message) label.textContent = message;
  }
}

// ---------- result ----------
function renderResult(r) {
  const root = $("#result");
  root.replaceChildren();
  root.className = "result show";

  const v = r.verdict;
  const risk = RISK[v.risk_level] || RISK.info;

  const banner = el("div", { class: "verdict" });
  banner.style.setProperty("--rc", risk.color);
  banner.style.borderColor = risk.color;
  banner.append(
    gauge(v.score, risk.color),
    el("div", { class: "vtext" }, el("div", { class: "level", text: risk.label }), el("div", { class: "headline", text: v.headline })),
  );
  root.append(banner);

  if (r.evidence_audit && r.evidence_audit.proposed > 0) {
    root.append(evidenceCheck(r.evidence_audit, r.rejected_claims || []));
  }

  if (v.tells && v.tells.length) root.append(tellsSection(r, risk.color));

  if (v.reasoning) {
    const sec = section("The read");
    sec.append(el("div", { class: "how", text: v.reasoning }));
    root.append(sec);
  }

  if (r.archetype && r.archetype.archetype_id !== "none" && r.archetype_how) {
    const sec = section("How this con usually works");
    const how = el("div", { class: "how" }, el("div", { class: "name", text: r.archetype.name }), el("div", { text: r.archetype_how }));
    if (r.archetype_refs && r.archetype_refs.length) {
      const refs = el("div", { class: "refs" }, "Basis ");
      r.archetype_refs.forEach((x, i) => refs.append(i ? ", " : "", link(x.url, x.name)));
      how.append(refs);
    }
    sec.append(how);
    root.append(sec);
  }

  if (r.sources && r.sources.length) {
    const sec = section("Live research");
    for (const s of r.sources) {
      const about = s.mentions && s.mentions.length ? `Mentions ${s.mentions.join(", ")}` : "About the scam pattern in general";
      sec.append(el("div", { class: "source" }, el("div", {}, link(s.url, s.title)), el("div", { class: "s-about", text: about }), el("div", { class: "s-snip", text: s.snippet })));
    }
    root.append(sec);
  }

  const ap = r.action_plan || {};
  if ((ap.do_now && ap.do_now.length) || (ap.do_not && ap.do_not.length)) {
    const sec = section("What to do");
    const cols = el("div", { class: "cols" });
    if (ap.do_now && ap.do_now.length) {
      const ul = el("ul");
      for (const s of ap.do_now) ul.append(el("li", {}, el("div", { text: s.step }), s.why ? el("div", { class: "why", text: s.why }) : null));
      cols.append(el("div", { class: "box do" }, el("h4", { text: "Do now" }), ul));
    }
    if (ap.do_not && ap.do_not.length) {
      const ul = el("ul");
      for (const s of ap.do_not) ul.append(el("li", { text: s }));
      cols.append(el("div", { class: "box dont" }, el("h4", { text: "Don’t" }), ul));
    }
    sec.append(cols);
    root.append(sec);
  }

  const notProven = r.not_proven || [];
  if (notProven.length || (ap.how_to_verify && ap.how_to_verify.length)) {
    const sec = section("What isn’t proven, and what would settle it");
    const cols = el("div", { class: "cols" });
    if (notProven.length) cols.append(listBox("box notproven", "Telltale can’t confirm", notProven));
    if (ap.how_to_verify && ap.how_to_verify.length) cols.append(listBox("box wouldchange", "What would settle it", ap.how_to_verify));
    sec.append(cols);
    root.append(sec);
  }

  if (ap.report_to && ap.report_to.length) {
    const sec = section("Where to report");
    for (const c of ap.report_to) {
      const card = el("div", { class: "report" }, el("div", { class: "r-name", text: c.region && c.region !== "Global" ? `${c.name} (${c.region})` : c.name }));
      const meta = el("div", { class: "r-meta" });
      if (c.phone) meta.append(`Phone ${c.phone}`);
      if (c.url) meta.append(c.phone ? "   " : "", link(c.url, c.url));
      if (c.phone || c.url) card.append(meta);
      if (c.note) card.append(el("div", { class: "r-note", text: c.note }));
      sec.append(card);
    }
    root.append(sec);
  }

  if (ap.safe_reply) {
    const sec = section("A safe reply you could send");
    const ta = el("textarea");
    ta.value = ap.safe_reply;
    ta.readOnly = true;
    const btn = el("button", { class: "btn copy", text: "Copy" });
    btn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(ap.safe_reply);
        btn.textContent = "Copied";
      } catch {
        ta.select();
        btn.textContent = "Select and copy";
      }
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    };
    sec.append(el("div", { class: "reply" }, ta, btn));
    root.append(sec);
  }

  const en = r.entities || {};
  const picked = [["link", en.domains], ["email", en.emails], ["phone", en.phones], ["UPI", en.upi_ids], ["wallet", en.crypto_addresses], ["amount", en.amounts]];
  const entChips = picked.flatMap(([label, arr]) => (arr || []).map((x) => el("span", { class: "entity" }, el("b", { text: label }), x)));
  if (entChips.length) {
    const sec = section("What we picked out");
    sec.append(el("div", { class: "entities" }, ...entChips));
    root.append(sec);
  }

  if (r.coverage_notes && r.coverage_notes.length) {
    root.append(el("div", { class: "notes" }, el("div", { text: "Notes on this analysis" }), el("ul", {}, ...r.coverage_notes.map((c) => el("li", { text: c })))));
  }
  const trace = runTrace(r);
  if (trace) root.append(trace);
  root.append(el("div", { class: "disclaimer", text: r.disclaimer || "" }));
  root.scrollIntoView({ behavior: "smooth", block: "start" });
}

function tellsSection(r, color) {
  const sources = Object.fromEntries((r.sources || []).map((s) => [s.id, s]));
  const signals = Object.fromEntries((r.signals || []).map((s) => [s.id, s]));
  const sec = section("The tells");
  for (const t of r.verdict.tells) {
    const card = el("div", { class: "tell" }, el("div", { class: "t-title", text: t.title }), el("div", { class: "t-exp", text: t.explanation }));
    card.style.setProperty("--rc", color);
    if (t.evidence_type === "quote" && t.quote) {
      card.append(el("div", { class: "quote", text: `“${t.quote}”` }), el("div", { class: "badge", text: "from the message" }));
    } else if (t.evidence_type === "source") {
      const src = sources[t.evidence_ref];
      if (t.support) card.append(el("div", { class: "quote", text: `“${t.support}”` }));
      if (src) card.append(el("div", { class: "t-src" }, "Source ", link(src.url, src.title)));
      card.append(el("div", { class: "badge", text: "live source" }));
    } else {
      const sig = signals[t.evidence_ref];
      if (sig) card.append(el("div", { class: "t-src", text: sig.evidence_text ? `Detector found ${sig.evidence_text}` : `Detector ${sig.label}` }));
      card.append(el("div", { class: "badge", text: "detected signal" }));
    }
    sec.append(card);
  }
  return sec;
}

// Proposed vs backed vs rejected. In deterministic mode "proposed" equals "backed" because
// the detectors only put forward what they found.
function evidenceCheck(audit, rejected) {
  const sec = section("Evidence check");
  sec.classList.add("evcheck");
  sec.append(
    el("div", {
      class: "ev-lead",
      text: "Every finding has to point at something checkable, such as a detector signal, a passage from a live source, or the message’s own words. Here is how this analysis held up.",
    }),
    el("div", { class: "ev-stats" }, evStat(audit.proposed, "proposed", "neutral"), evStat(audit.kept, "backed by evidence", "ok"), evStat(audit.rejected, "rejected", audit.rejected > 0 ? "bad" : "muted")),
  );
  if (rejected.length) {
    const box = el("div", { class: "ev-rejects" }, el("div", { class: "ev-rejects-h", text: "The model proposed these, but the evidence couldn’t back them, so they were dropped." }));
    for (const claim of rejected) {
      box.append(
        el(
          "div",
          { class: "ev-claim" },
          el("div", { class: "ev-claim-src", text: "Nemotron proposed" }),
          el("div", { class: "ev-claim-top" }, el("span", { class: "ev-claim-title", text: claim.title || "Untitled claim" }), el("span", { class: "ev-claim-badge", text: "✗ rejected" })),
          el("div", { class: "ev-claim-reason", text: `Dropped because it ${claim.reason}.` }),
        ),
      );
    }
    sec.append(box);
  } else {
    sec.append(el("div", { class: "ev-clean", text: "Every finding the model proposed was backed by evidence, so nothing had to be dropped." }));
  }
  return sec;
}

// Which model or tool ran each step, in what reasoning mode, and what it cost.
function runTrace(r) {
  const rows = r.run_trace || [];
  if (!rows.length) return null;
  const calls = rows.filter((x) => x.kind === "model");
  const searches = rows.length - calls.length;
  const tokens = calls.reduce((a, x) => a + x.tokens_in + x.tokens_out, 0);
  const summary = `How this run worked. ${calls.length} model call${calls.length === 1 ? "" : "s"}, ${searches} live search${searches === 1 ? "" : "es"}, ${fmtMs(r.duration_ms || 0)} in total`;
  const head = el("tr", {}, ...["Step", "Model or tool", "Mode", "Time", "Tokens in / out"].map((h) => el("th", { text: h })));
  const body = rows.map((x) =>
    el(
      "tr",
      { class: x.ok ? "" : "fail" },
      el("td", { text: STAGE_NAMES[x.stage] || x.stage }),
      el("td", { text: x.kind === "model" ? x.name.split("/").pop() : "Tavily", attrs: { title: x.kind === "model" ? x.name : x.detail } }),
      el("td", { text: x.kind === "model" ? x.detail || "" : `${x.results} results${x.credits ? `, ${x.credits} credits` : ""}` }),
      el("td", { class: "num", text: fmtMs(x.ms) }),
      el("td", { class: "num", text: x.kind === "model" ? `${x.tokens_in} / ${x.tokens_out}` : "" }),
    ),
  );
  return el(
    "details",
    { class: "trace" },
    el("summary", { text: summary }),
    el("div", { class: "trace-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body))),
    el("div", { class: "trace-note", text: `${tokens.toLocaleString()} tokens across all model calls. Reasoning runs only on the verdict step.` }),
  );
}

function listBox(cls, heading, items) {
  return el("div", { class: cls }, el("h4", { text: heading }), el("ul", {}, ...items.map((s) => el("li", { text: s }))));
}

function evStat(n, label, kind) {
  return el("div", { class: "ev-stat " + kind }, el("div", { class: "ev-num", text: String(n) }), el("div", { class: "ev-lbl", text: label }));
}

function gauge(score, color) {
  const NS = "http://www.w3.org/2000/svg";
  const r = 40;
  const c = 2 * Math.PI * r;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 92 92");
  svg.setAttribute("class", "g");
  const ring = (stroke, extra = {}) => {
    const n = document.createElementNS(NS, "circle");
    for (const [k, v] of Object.entries({ cx: 46, cy: 46, r, fill: "none", stroke, "stroke-width": 8, ...extra })) n.setAttribute(k, v);
    return n;
  };
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  svg.append(ring("#22304a"), ring(color, { "stroke-linecap": "round", "stroke-dasharray": c, "stroke-dashoffset": off, transform: "rotate(-90 46 46)" }));
  return el("div", { class: "gauge" }, svg, el("div", { class: "num", text: String(score) }));
}

function section(title) {
  return el("div", { class: "section" }, el("h3", { text: title }));
}

function setBusy(b) {
  const btn = $("#go");
  btn.disabled = b;
  btn.textContent = b ? "Checking…" : "Check it";
}

function flash(m) {
  const b = $("#errBanner");
  b.textContent = m;
  b.style.display = "block";
}

boot();
