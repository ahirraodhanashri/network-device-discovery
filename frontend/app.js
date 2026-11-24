"use strict";

/* ------------------------------------------------------------------ helpers */
const API = (localStorage.getItem("nd_api") || "/api").replace(/\/$/, "");
const $ = (id) => document.getElementById(id);

/** Tiny DOM builder. Strings become text nodes, so network data can never inject HTML. */
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) if (child != null && child !== false) node.append(child);
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(API + path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({ error: "Invalid server response" }));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

const ipKey = (ip) => ip.split(".").reduce((n, part) => n * 256 + Number(part), 0);
const setMessage = (text) => { $("message").textContent = text; };
const clear = (node) => node.replaceChildren();

/* -------------------------------------------------------------------- state */
let devicesInView = [];
let gatewayInView = null;
let flaggedIps = new Set();

/* -------------------------------------------------------------- status chips */
function renderChips(health) {
  const chips = [h("span", { class: "chip" }, "● API online")];
  chips.push(health.scapy_available
    ? h("span", { class: "chip" }, "Scapy ready (ARP)")
    : h("span", { class: "chip warn" }, "Scapy missing: ARP unavailable, demo still works"));
  chips.push(health.ping_available
    ? h("span", { class: "chip" }, "ping ready (ICMP)")
    : h("span", { class: "chip warn" }, "ping not found"));
  if (health.local_ip) chips.push(h("span", { class: "chip" }, "You: " + health.local_ip));
  if (health.gateway_ip) chips.push(h("span", { class: "chip" }, "Gateway: " + health.gateway_ip));
  $("chips").replaceChildren(...chips);
}

/* ------------------------------------------------------ 1. subnet calculator */
let subnetTimer = null;
async function renderSubnetInfo() {
  const box = $("subnetInfo");
  try {
    const i = await api("/subnet-info?cidr=" + encodeURIComponent($("subnet").value));
    const item = (label, value, wide) => h("div", { class: "item" + (wide ? " wide" : "") },
      h("span", {}, label), h("b", {}, value));
    box.replaceChildren(
      item("Network address", i.network_address),
      item("Broadcast address", i.broadcast_address),
      item("Subnet mask", `${i.netmask}  (/${i.prefix_length})`),
      item("Wildcard mask", i.wildcard_mask),
      item("Usable hosts", `${i.usable_hosts} of ${i.total_addresses} addresses`),
      item("Host range", `${i.first_host} – ${i.last_host}`),
      item("Class / private block", `${i.address_class} · ${i.private_block || "public"}`),
      item("Mask in binary", i.netmask_binary, true),
      h("div", { class: "item" }, h("span", {}, "Scannable here?"),
        h("b", {}, i.scannable ? "Yes" : "No: private LAN, max 1024 addresses")),
    );
  } catch (error) {
    box.replaceChildren(h("div", { class: "info-error" }, error.message));
  }
}

/* ------------------------------------------------------------------ scanning */
function selectedMethods() {
  const methods = [];
  if ($("mArp").checked) methods.push("arp");
  if ($("mIcmp").checked) methods.push("icmp");
  if ($("mTcp").checked) methods.push("tcp");
  return methods;
}

function updateFormState() {
  const isDemo = $("source").value !== "";
  $("authRow").classList.toggle("hidden", isDemo);
  $("portsField").classList.toggle("hidden", !$("mTcp").checked);
}

async function runScan() {
  const demo = $("source").value;
  const methods = selectedMethods();
  if (!methods.includes("arp") && !methods.includes("icmp")) {
    return setMessage("Select ARP and/or ICMP. TCP scanning only probes hosts found by those.");
  }
  if (!demo && !$("authorized").checked) {
    return setMessage("Please confirm you are authorised to scan this network.");
  }
  const button = $("scanBtn");
  button.disabled = true;
  button.textContent = "Scanning…";
  setMessage("Scanning. ARP takes a few seconds; ICMP and TCP sweeps of a /24 can take up to a minute.");
  $("scanStatus").textContent = "Running";
  try {
    const scan = await api("/scans", {
      method: "POST",
      body: JSON.stringify({
        subnet: $("subnet").value, methods, ports: $("ports").value,
        authorized: $("authorized").checked, demo: demo || null,
      }),
    });
    showScan(scan, scan.changes_since_previous);
    setMessage(`Scan #${scan.scan_id} (${scan.method}) completed: ${scan.device_count} device(s).`
      + (scan.notes.length ? "\n" + scan.notes.join("\n") : ""));
  } catch (error) {
    $("scanStatus").textContent = "Error";
    setMessage(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Start discovery ↗";
    await loadHistory();
  }
}

/** Put one scan result (fresh or saved) on screen. */
function showScan(scan, changes) {
  devicesInView = scan.devices || [];
  gatewayInView = scan.gateway_ip || null;
  const anomalies = scan.anomalies || [];
  const macChanged = (changes && changes.mac_changed) || [];

  flaggedIps = new Set();
  anomalies.forEach((a) => a.ip.split(",").forEach((ip) => flaggedIps.add(ip.trim())));
  macChanged.forEach((c) => flaggedIps.add(c.ip));

  $("demoBanner").classList.toggle("hidden", !scan.is_demo);
  $("scanStatus").textContent = scan.status;
  $("alertCount").textContent = anomalies.length + macChanged.length;
  renderAlerts(anomalies, changes);
  renderMethodComparison(scan.method_comparison);
  renderDevices();
  renderTopology();
}

/* ------------------------------------------------------------ 2. alerts view */
function renderAlerts(anomalies, changes) {
  const box = $("alerts");
  clear(box);
  const macChanged = (changes && changes.mac_changed) || [];

  if (!anomalies.length && !macChanged.length) {
    box.append(h("div", { class: "ok-box" },
      "No ARP-spoofing indicators in this scan. This is not proof of safety: it only means that no duplicate "
      + "MACs or MAC changes were observed."));
  }
  anomalies.forEach((a) => box.append(alertNode(a.severity, a.message)));
  if (changes) {
    box.append(h("h3", {}, `Changes since scan #${changes.previous_scan_id}`));
    box.append(changesView(changes));
  }
}

function alertNode(severity, message) {
  return h("div", { class: "alert " + severity },
    h("span", { class: "tag" }, severity), message);
}

function ipPills(items, label) {
  return h("div", {},
    h("div", { class: "muted small" }, `${label} (${items.length})`),
    h("div", { class: "iplist" }, items.length
      ? items.map((d) => h("span", { class: "pill" }, d.hostname ? `${d.ip} · ${d.hostname}` : d.ip))
      : h("span", { class: "muted small" }, "none")));
}

/** Shared by the "changes since previous scan" box and the manual compare tool. */
function changesView(changes) {
  const wrap = h("div");
  (changes.mac_changed || []).forEach((c) => wrap.append(alertNode(c.severity, c.message)));
  wrap.append(h("div", { style: "display:grid;gap:12px;margin-top:8px" },
    ipPills(changes.newly_observed, "Newly observed"),
    ipPills(changes.not_observed_in_new_scan, "Not observed this time")));
  wrap.append(h("p", { class: "muted small" }, changes.note));
  return wrap;
}

function renderMethodComparison(cmp) {
  $("comparisonCard").classList.toggle("hidden", !cmp);
  if (!cmp) return;
  const list = (label, ips) => h("div", {}, h("div", { class: "muted small" }, `${label} (${ips.length})`),
    h("div", { class: "iplist" }, ips.length ? ips.map((ip) => h("span", { class: "pill" }, ip))
      : h("span", { class: "muted small" }, "none")));
  $("methodComparison").replaceChildren(
    h("div", { style: "display:grid;gap:12px" },
      list("Found by both ARP and ICMP", cmp.both),
      list("ARP only: alive but ignoring ping", cmp.arp_only),
      list("ICMP only", cmp.icmp_only)),
    h("p", { class: "muted small" }, cmp.explanation));
}

/* ------------------------------------------------------------ 3. device table */
function renderDevices() {
  const query = $("search").value.toLowerCase();
  const rows = devicesInView.filter((d) =>
    [d.ip, d.mac, d.vendor, d.hostname].join(" ").toLowerCase().includes(query));
  $("deviceCount").textContent = devicesInView.length;

  const body = $("deviceRows");
  if (!rows.length) {
    body.replaceChildren(h("tr", {}, h("td", { colspan: 8, class: "empty" },
      devicesInView.length ? "No matching devices." : "No devices found.")));
    return;
  }
  body.replaceChildren(...rows.map((d) => h("tr", { class: flaggedIps.has(d.ip) ? "flagged" : "" },
    h("td", {}, h("b", {}, d.ip), d.is_gateway ? h("span", { class: "pill gw" }, "gateway") : null),
    h("td", {}, d.mac || "—", d.mac ? null : h("span", { class: "sub" }, "needs ARP")),
    h("td", {}, d.vendor || "—"),
    h("td", {}, d.hostname || "—"),
    h("td", {}, d.rtt_ms != null ? `${d.rtt_ms} ms` : "—"),
    h("td", {}, d.ttl != null ? String(d.ttl) : "—", d.os_hint ? h("span", { class: "sub" }, d.os_hint) : null),
    h("td", {}, d.open_ports.length
      ? d.open_ports.map((p) => h("span", { class: "pill port" }, `${p.port}/${p.service}`)) : "—"),
    h("td", {}, d.methods.map((m) => h("span", { class: "pill" }, m))))));
}

/* ------------------------------------------------------------ topology (SVG) */
function svg(tag, attrs = {}, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text != null) node.textContent = text;
  return node;
}

function renderTopology() {
  const box = $("topology");
  if (!devicesInView.length) {
    box.replaceChildren(h("div", { class: "empty" }, "No devices to draw."));
    return;
  }
  const width = 760, height = 440, cx = width / 2, cy = height / 2;
  const gateway = devicesInView.find((d) => d.is_gateway);
  const others = devicesInView.filter((d) => !d.is_gateway);
  const canvas = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img",
                              "aria-label": "Logical network map" });

  others.forEach((device, index) => {   // links first, so nodes are drawn on top
    const angle = (2 * Math.PI * index) / others.length - Math.PI / 2;
    device._x = cx + 290 * Math.cos(angle);
    device._y = cy + 160 * Math.sin(angle);
    canvas.append(svg("line", { x1: cx, y1: cy, x2: device._x, y2: device._y, stroke: "#26334d", "stroke-width": 1.5 }));
  });
  canvas.append(
    svg("circle", { cx, cy, r: 26, fill: "#3d3216", stroke: "#ffd18b", "stroke-width": 2 }),
    svg("text", { x: cx, y: cy + 4, "text-anchor": "middle" }, gateway ? "GW" : "LAN"),
    svg("text", { x: cx, y: cy + 44, "text-anchor": "middle" }, gateway ? gateway.ip : "(gateway not seen)"));

  others.forEach((d) => {
    const flagged = flaggedIps.has(d.ip);
    canvas.append(
      svg("circle", { cx: d._x, cy: d._y, r: 14, fill: flagged ? "#4a1f27" : "#163d37",
                      stroke: flagged ? "#ff8f8f" : "#6be3c1", "stroke-width": 2 }),
      svg("text", { x: d._x, y: d._y + 30, "text-anchor": "middle" }, d.ip),
      svg("text", { x: d._x, y: d._y + 42, "text-anchor": "middle", class: "sub" }, d.hostname || d.vendor || ""));
  });
  box.replaceChildren(canvas);
}

/* -------------------------------------------------------- 4. packet anatomy */
async function loadPacket() {
  const box = $("packet");
  try {
    const p = await api("/packet/arp?target=" + encodeURIComponent($("pktTarget").value));
    const row = (f) => h("tr", {}, h("td", {}, f.layer), h("td", {}, h("b", {}, f.field)),
      h("td", {}, `${f.offset}–${f.offset + f.length - 1}`), h("td", {}, h("code", {}, f.hex)),
      h("td", {}, f.value), h("td", { class: "muted" }, f.meaning));
    box.replaceChildren(
      h("p", {}, p.description + `  (${p.length_bytes} bytes)`),
      h("div", { class: "table-wrap packet-table" }, h("table", { style: "min-width:760px" },
        h("thead", {}, h("tr", {}, ["Layer", "Field", "Bytes", "Hex", "Value", "Meaning"].map((t) => h("th", {}, t)))),
        h("tbody", {}, p.fields.map(row)))),
      h("pre", { class: "hexdump" }, p.hexdump),
      h("p", { class: "muted small" }, p.note));
  } catch (error) {
    box.replaceChildren(h("div", { class: "info-error" }, error.message));
  }
}

/* ------------------------------------------------- 5. history and comparison */
async function loadHistory() {
  const box = $("history");
  try {
    const scans = await api("/scans");
    $("scanCount").textContent = scans.length;
    fillCompareSelects(scans);
    if (!scans.length) return box.replaceChildren(h("div", { class: "empty" }, "No saved scans yet."));
    box.replaceChildren(...scans.map((s) => h("div", { class: "history-item" },
      h("div", {},
        h("b", {}, `Scan #${s.id}`), h("span", { class: "muted" }, ` · ${s.subnet} · ${s.method}`),
        s.is_demo ? h("span", { class: "demo-tag" }, "SIMULATED") : null,
        h("div", { class: "muted small" }, s.started_at)),
      h("div", { class: "btns" },
        h("span", {}, `${s.device_count} devices · ${s.status}`),
        s.status === "completed" ? h("a", { class: "btn-link", href: `${API}/scans/${s.id}/export.csv` }, "CSV ↓") : null,
        h("button", { class: "secondary", onclick: () => openScan(s.id) }, "View"),
        h("button", { class: "danger", onclick: () => removeScan(s.id) }, "Delete")))));
  } catch (error) {
    box.replaceChildren(h("div", { class: "empty" }, "Could not load history: " + error.message));
  }
}

function fillCompareSelects(scans) {
  const done = scans.filter((s) => s.status === "completed");
  const options = () => done.map((s) =>
    h("option", { value: s.id }, `#${s.id} · ${s.subnet} · ${s.method} · ${s.device_count} devices`));
  $("cmpOld").replaceChildren(...options());
  $("cmpNew").replaceChildren(...options());
  if (done.length > 1) $("cmpOld").selectedIndex = 1;   // list is newest-first
}

async function openScan(id) {
  try {
    const scan = await api("/scans/" + id);
    showScan(scan, null);
    setMessage(`Showing saved scan #${id} from ${scan.started_at}`);
    $("alertsCard").scrollIntoView({ behavior: "smooth" });
  } catch (error) {
    setMessage(error.message);
  }
}

async function removeScan(id) {
  if (!confirm(`Delete scan #${id}?`)) return;
  try { await api("/scans/" + id, { method: "DELETE" }); } catch (error) { setMessage(error.message); }
  await loadHistory();
}

async function compareScans() {
  const box = $("compareResult");
  const oldId = $("cmpOld").value, newId = $("cmpNew").value;
  if (!oldId || !newId) return box.replaceChildren(h("div", { class: "empty" }, "Need two completed scans."));
  try {
    const result = await api(`/scans/compare?old=${oldId}&new=${newId}`);
    box.replaceChildren(...[
      h("h3", {}, `Scan #${oldId} → scan #${newId}`),
      result.mixed_sources ? alertNode("medium", "One scan is simulated and the other is real: this comparison is meaningless.") : null,
      changesView(result),
    ].filter(Boolean));   // replaceChildren(null) would insert the text "null"
  } catch (error) {
    box.replaceChildren(h("div", { class: "info-error" }, error.message));
  }
}

/* --------------------------------------------------------------------- start */
async function init() {
  $("scanBtn").addEventListener("click", runScan);
  $("search").addEventListener("input", renderDevices);
  $("pktBtn").addEventListener("click", loadPacket);
  $("cmpBtn").addEventListener("click", compareScans);
  $("source").addEventListener("change", updateFormState);
  $("mTcp").addEventListener("change", updateFormState);
  $("subnet").addEventListener("input", () => { clearTimeout(subnetTimer); subnetTimer = setTimeout(renderSubnetInfo, 300); });

  try {
    const health = await api("/health");
    renderChips(health);
    Object.entries(health.demo_variants || {}).forEach(([key, text]) =>
      $("source").append(h("option", { value: key }, "DEMO (simulated): " + text)));
    if (health.gateway_ip) {
      $("pktTarget").value = health.gateway_ip;
      $("subnet").value = health.gateway_ip.replace(/\.\d+$/, ".0/24");
    }
    if (!health.scapy_available) setMessage("Scapy is not available, so real ARP scans will fail. "
      + "Install the requirements, or use a DEMO data source to rehearse.");
  } catch (error) {
    $("chips").replaceChildren(h("span", { class: "chip bad" }, "● API offline"));
    setMessage("Start the Flask backend (python app.py) and reload. " + error.message);
  }
  updateFormState();
  renderSubnetInfo();
  loadPacket();
  loadHistory();
}
init();
