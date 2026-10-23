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

// Colours live in styles.css as --critical, --high and so on. Here each level only names its class.
const RISK = {
  critical: { cls: "risk-critical", label: "Critical, almost certainly a scam" },
  high: { cls: "risk-high", label: "High, likely a scam" },
  medium: { cls: "risk-medium", label: "Suspicious, verify before acting" },
  low: { cls: "risk-low", label: "Low, probably legitimate" },
  info: { cls: "risk-info", label: "No strong scam signals found" },
};

// The same cut-offs as risk_band() in backend/verify.py, used to draw the score scale.
const BANDS = [
  ["info", 0],
  ["low", 15],
  ["medium", 35],
  ["high", 60],
  ["critical", 80],
];

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

// A scam checker shouldn't ask anyone to click blind, so every outside link shows its domain.
function hostOf(url) {
  try {
    const u = new URL(url, location.href);
    if (u.protocol === "https:" || u.protocol === "http:") return u.hostname.replace(/^www\./, "");
  } catch {
    /* not a URL */
  }
  return "";
}

function srcLink(url, text) {
  const host = hostOf(url);
  return el("span", { class: "src" }, link(url, text), host ? el("span", { class: "host", text: host }) : null);
}

// Tap to call on a phone. Only digits, spaces, dashes and a leading plus make it into the href.
function telLink(phone) {
  const digits = String(phone).replace(/[\s-]/g, "");
  if (!/^\+?\d{3,15}$/.test(digits)) return el("span", { text: String(phone) });
  return el("a", { text: String(phone), attrs: { href: "tel:" + digits } });
}

// A collapsed section. The summary stays visible, so a reader can see what's inside without opening it.
function fold(title, count, ...body) {
  return el(
    "details",
    { class: "fold" },
    el("summary", {}, el("span", { text: title }), count ? el("span", { class: "count", text: count }) : null),
    el("div", { class: "fold-body" }, ...body),
  );
}

function plural(n, one, many = one + "s") {
  return `${n} ${n === 1 ? one : many}`;
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

// ---------- install ----------
// Where the browser offers it (Chrome on Android and desktop), show an Install button. Installed on
// Android, Telltale appears in the share sheet and receives the message through ?text= (see boot).
let installPrompt = null;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  installPrompt = e;
  $("#installBtn").hidden = false;
});
window.addEventListener("appinstalled", () => {
  installPrompt = null;
  $("#installBtn").hidden = true;
});
$("#installBtn").addEventListener("click", async () => {
  if (!installPrompt) return;
  installPrompt.prompt();
  await installPrompt.userChoice.catch(() => {});
  installPrompt = null;
  $("#installBtn").hidden = true;
});

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
  t.hidden = false;
});

function clearFile() {
  pickedFile = null;
  $("#file").value = "";
  $("#thumb").hidden = true;
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
// Order follows what a worried person needs: the verdict, what to do about it, a short why, and
// then the working, folded away for anyone who wants to check it.
function renderResult(r) {
  const root = $("#result");
  root.replaceChildren();
  root.className = "result show";

  const v = r.verdict;
  const risk = RISK[v.risk_level] || RISK.info;
  const ap = r.action_plan || {};
  // Reporting channels sit beside the actions when a message looks like a scam. On a low-risk
  // result they would only alarm someone, so they move down with the rest of the detail.
  const serious = ["medium", "high", "critical"].includes(v.risk_level);

  root.append(verdictBlock(v, risk));

  if ((ap.do_now && ap.do_now.length) || (ap.do_not && ap.do_not.length)) {
    const sec = section("What to do");
    sec.classList.add("todo");
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

  // reporting.yaml lists each region's most direct channels first (the national helpline or portal,
  // then the next one, or your bank where there's only one), so two stay in view and the rest fold.
  const channels = ap.report_to || [];
  if (channels.length && serious) {
    const sec = section("Where to report it");
    sec.append(reportList(channels.slice(0, 2)));
    if (channels.length > 2) sec.append(fold(plural(channels.length - 2, "more place") + " to report", "", reportList(channels.slice(2))));
    root.append(sec);
  }

  if (ap.safe_reply) root.append(safeReply(ap.safe_reply));

  if (r.evidence_audit && r.evidence_audit.proposed > 0) {
    root.append(evidenceCheck(r.evidence_audit, r.rejected_claims || []));
  }
  if (v.tells && v.tells.length) {
    root.append(tellsSection(r, risk.cls));
  } else if (!serious) {
    const sec = section("Why it’s rated low");
    const said = (r.signals || []).length
      ? "A few minor signals came up, but none of them was strong enough to raise the risk."
      : "Telltale’s detectors look for look-alike links, payment demands, requests for codes or remote access, and pressure to act fast. None of them fired on this message.";
    sec.append(el("p", { class: "section-lead", text: said }));
    root.append(sec);
  }
  if (r.coverage_notes && r.coverage_notes.length) {
    root.append(el("div", { class: "notes" }, el("ul", {}, ...r.coverage_notes.map((c) => el("li", { text: c })))));
  }

  const folds = [];
  if (v.reasoning) folds.push(fold("The full read", "", el("div", { class: "how", text: v.reasoning })));

  if (r.archetype && r.archetype.archetype_id !== "none" && r.archetype_how) {
    const how = el("div", { class: "how" }, el("div", { class: "name", text: r.archetype.name }), el("div", { text: r.archetype_how }));
    if (r.archetype_refs && r.archetype_refs.length) {
      const refs = el("div", { class: "refs" }, "Basis ");
      r.archetype_refs.forEach((x, i) => refs.append(i ? ", " : "", srcLink(x.url, x.name)));
      how.append(refs);
    }
    folds.push(fold("How this con usually works", "", how));
  }

  if (r.sources && r.sources.length) {
    const list = r.sources.map((s) => {
      const about = s.mentions && s.mentions.length ? `Mentions ${s.mentions.join(", ")}` : "About the scam pattern in general";
      return el("div", { class: "source" }, srcLink(s.url, s.title), el("div", { class: "s-about", text: about }), el("div", { class: "s-snip", text: s.snippet }));
    });
    folds.push(fold("Live research, via Tavily", plural(r.sources.length, "source"), ...list));
  }

  const notProven = r.not_proven || [];
  if (notProven.length || (ap.how_to_verify && ap.how_to_verify.length)) {
    const cols = el("div", { class: "cols" });
    if (notProven.length) cols.append(listBox("box notproven", "Telltale can’t confirm", notProven));
    if (ap.how_to_verify && ap.how_to_verify.length) cols.append(listBox("box wouldchange", "What would settle it", ap.how_to_verify));
    folds.push(fold("What isn’t proven, and what would settle it", "", cols));
  }

  if (channels.length && !serious) folds.push(fold("Where to report a scam", plural(channels.length, "place"), reportList(channels)));

  const en = r.entities || {};
  const picked = [["link", en.domains], ["email", en.emails], ["phone", en.phones], ["UPI", en.upi_ids], ["wallet", en.crypto_addresses], ["amount", en.amounts]];
  const entChips = picked.flatMap(([label, arr]) => (arr || []).map((x) => el("span", { class: "entity" }, el("b", { text: label }), x)));
  if (entChips.length) folds.push(fold("What Telltale picked out of the message", plural(entChips.length, "item"), el("div", { class: "entities" }, ...entChips)));

  const trace = runTrace(r);
  if (trace) folds.push(trace);

  if (folds.length) {
    root.append(
      el(
        "div",
        { class: "more" },
        el("h3", { text: "How Telltale got here" }),
        el("p", { class: "section-lead", text: "The reasoning, the sources it checked, and what each model call cost. Open any line." }),
        ...folds,
      ),
    );
  }

  root.append(el("div", { class: "disclaimer", text: r.disclaimer || "" }));
  root.scrollIntoView({ behavior: "smooth", block: "start" });
}

function verdictBlock(v, risk) {
  const score = Math.max(0, Math.min(100, Math.round(Number(v.score) || 0)));
  let active = BANDS[0][0];
  for (const [name, from] of BANDS) if (score >= from) active = name;
  const track = el("div", { class: "v-track" }, ...BANDS.map(([name]) => el("span", { class: `band b-${name}${name === active ? " on" : ""}` })));
  const mark = el("span", { class: "v-mark" }, el("span", { text: String(score) }));
  mark.style.setProperty("--pos", score + "%");
  track.append(mark);
  const ticks = el("div", { class: "v-ticks", attrs: { "aria-hidden": "true" } }, ...["0", "15", "35", "60", "80", "100"].map((t) => el("span", { text: t })));
  const scale = el(
    "div",
    { class: "v-scale", attrs: { role: "img", "aria-label": `Risk score ${score} out of 100` } },
    el("div", { class: "v-cap", attrs: { "aria-hidden": "true" }, text: "Risk score out of 100" }),
    track,
    ticks,
  );
  return el("div", { class: "verdict " + risk.cls }, el("div", { class: "v-stamp", text: risk.label }), el("h2", { class: "v-headline", text: v.headline }), scale);
}

function reportList(channels) {
  const box = el("div", { class: "reports" });
  for (const c of channels) {
    const row = el("div", { class: "report" }, el("div", { class: "r-name", text: c.region && c.region !== "Global" ? `${c.name} (${c.region})` : c.name }));
    if (c.phone || c.url) {
      const meta = el("div", { class: "r-meta" });
      if (c.phone) meta.append(el("span", {}, "Call ", telLink(c.phone)));
      if (c.url) meta.append(link(c.url, hostOf(c.url) || c.url));
      row.append(meta);
    }
    if (c.note) row.append(el("div", { class: "r-note", text: c.note }));
    box.append(row);
  }
  return box;
}

function safeReply(text) {
  const sec = section("A safe reply you could send");
  const ta = el("textarea", { attrs: { "aria-label": "Suggested reply" } });
  ta.value = text;
  ta.readOnly = true;
  const btn = el("button", { class: "btn copy", text: "Copy" });
  btn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
    } catch {
      ta.select();
      btn.textContent = "Select and copy";
    }
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  };
  sec.append(el("div", { class: "reply" }, ta, btn));
  return sec;
}

function tellsSection(r, riskCls) {
  const sources = Object.fromEntries((r.sources || []).map((s) => [s.id, s]));
  const signals = Object.fromEntries((r.signals || []).map((s) => [s.id, s]));
  const sec = section("The tells");
  sec.classList.add(riskCls);
  const list = el("ol", { class: "findings" });
  for (const t of r.verdict.tells) {
    const item = el("li", { class: "tell" }, el("div", { class: "t-title", text: t.title }), el("div", { class: "t-exp", text: t.explanation }));
    if (t.evidence_type === "quote" && t.quote) {
      item.append(el("blockquote", { class: "quote", text: `“${t.quote}”` }), el("div", { class: "t-ev" }, el("span", { class: "badge", text: "From the message" })));
    } else if (t.evidence_type === "source") {
      const src = sources[t.evidence_ref];
      if (t.support) item.append(el("blockquote", { class: "quote", text: `“${t.support}”` }));
      item.append(el("div", { class: "t-ev" }, el("span", { class: "badge", text: "Live source via Tavily" }), src ? srcLink(src.url, src.title) : null));
    } else {
      const sig = signals[t.evidence_ref];
      const found = sig ? (sig.evidence_text ? `Matched “${sig.evidence_text}”` : sig.label) : null;
      item.append(el("div", { class: "t-ev" }, el("span", { class: "badge", text: "Detected signal" }), found ? el("span", { text: found }) : null));
    }
    list.append(item);
  }
  sec.append(list);
  return sec;
}

// Proposed vs backed vs rejected. In deterministic mode "proposed" equals "backed" because
// the detectors only put forward what they found.
function evidenceCheck(audit, rejected) {
  const sec = section("Evidence check");
  sec.classList.add("evcheck");
  const row = (label, n, cls) => el("div", { class: "row " + cls }, el("dt", { text: label }), el("dd", { text: String(n) }));
  sec.append(
    el("p", {
      class: "ev-lead",
      text: "Every finding has to point at something checkable, such as a detector signal, a passage from a live source, or the message’s own words. Here is how this analysis held up.",
    }),
    el(
      "dl",
      { class: "ledger" },
      row("Proposed by the model", audit.proposed, ""),
      row("Backed by evidence", audit.kept, "ok"),
      row("Rejected", audit.rejected, audit.rejected > 0 ? "bad" : "zero"),
    ),
  );
  if (rejected.length) {
    const box = el("div", { class: "ev-rejects" }, el("div", { class: "ev-rejects-h", text: "The model proposed these, but the evidence couldn’t back them, so they were dropped." }));
    for (const claim of rejected) {
      box.append(
        el(
          "div",
          { class: "ev-claim" },
          el("div", { class: "ev-claim-src", text: "Nemotron proposed" }),
          el("div", { class: "ev-claim-top" }, el("span", { class: "ev-claim-title", text: claim.title || "Untitled claim" }), el("span", { class: "ev-claim-badge", text: "Rejected" })),
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
  const count = `${plural(calls.length, "model call")}, ${plural(searches, "live search", "live searches")}, ${fmtMs(r.duration_ms || 0)}`;
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
  const d = fold(
    "How this run worked",
    count,
    el("div", { class: "trace-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body))),
    el("div", { class: "trace-note", text: `${tokens.toLocaleString()} tokens across all model calls. Reasoning runs only on the verdict step.` }),
  );
  d.classList.add("trace");
  return d;
}

function listBox(cls, heading, items) {
  return el("div", { class: cls }, el("h4", { text: heading }), el("ul", {}, ...items.map((s) => el("li", { text: s }))));
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
