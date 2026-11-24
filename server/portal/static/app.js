// Firewall Testkit portal. No dependencies.
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const api = (p, o) => fetch("api/" + p, o).then(async (r) => { if (!r.ok) throw new Error(await r.text()); return r.json(); });
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const I18N = {
  en: {
    kicker: "Security validation", title: "Firewall Testkit", tab_tests: "Tests", tab_settings: "Settings", tab_fwconfig: "Firewall configuration",
    manual: "Manual", control: "control agent", scope: "needs extra infrastructure", procedure: "Procedure", expected_res: "Expected result", bp: "Check Point best practices",
    fw_title: "Firewall configuration for the tests", fw_intro: "What the firewall under test must have configured so that the automated checks are meaningful. Vendor-neutral: apply it with the tools of each solution. Each case also lists its own prerequisites.",
    fw_cp: "Check Point: recommended baseline", fw_cp_intro: "Configuration best practices for Check Point CloudGuard Network / Cloud Firewall. The kit's checkpoint/ folder applies the testkit baseline through the Management API.",
    fw_cases: "Prerequisites per case", fw_manual: "Manual cases", fw_manual_intro: "Cases that are validated by following a procedure (console, cloud, integrations). Open them in the Tests tab to see the steps.",
    sol_none: "no solution configured (Settings)", compare: "Compare selected", compare_es: "ES", compare_help: "Tick two or more runs to compare solutions.",
    set_solution: "Solution under test", set_solution_help: "Name shown in reports and used to label runs (e.g. vendor and product). Change it before testing another solution.",
    sol_name: "Solution name", sol_vendor: "Vendor", vendor_cp: "Check Point", vendor_other: "Other",
    set_server: "Test server", set_server_help: "Workload IP of the test server (detected automatically). If the server is in one of the environments, select it below instead.",
    col_cidr: "CIDR", add_agents: "Add connected clients",
    set_ca: "TLS inspection CA", set_ca_help: "Public certificate (PEM) of the CA the solution uses to re-sign inspected TLS. Clients add it to their trust store; it also tells the checks which certificates were decrypted.",
    clients: "Clients", no_clients: "Waiting for clients…", search: "Search case or check (e.g. TLS, EICAR, IPS-06)", run_sel: "Run selection",
    run_all: "Run all", runs: "Runs", runs_help: "Pick one to see its results next to each check. When it finishes, download the Word report.",
    selected: (n) => `${n} checks selected`, run_case: "Run case", objective: "Objective", requires: "Firewall configuration needed", how: "Check Point notes",
    evidence: "Evidence", test: "Check", expected: "Expected", result: "Result", informative: "informative", ready: "ready", busy: "busy", offline: "offline",
    no_runs: "No runs yet.", finished: "finished", running: "running", report_en: "Report EN", report_es: "Report ES", fail: "failed", info: "info", na: "n/a",
    no_match: "No case matches the search.", no_agent: "No connected client is selected.",
    set_intro: "Describe the customer architecture: environments and their workload IPs, which one hosts the test server, the allowed matrix between environments and the roles used by some checks. Agents receive this configuration with every run.",
    set_envs: "Environments", set_envs_help: "Name must match TESTKIT_ENV of the client in that environment. IP = workload IP (the one that crosses the firewall).",
    col_name: "Name", col_ip: "Workload IP", col_desc: "Description", col_server: "Test server", col_peer: "Cross-AZ peer", add_env: "Add environment",
    set_matrix: "Segmentation matrix", set_matrix_help: "Services allowed from each source (row) to each destination. Anything unchecked is expected to be blocked.",
    always: "Allowed between all environments:", set_roles: "Roles", set_roles_help: "Environments used by checks that depend on specific policy rules. Leave empty to skip those checks.",
    set_internet: "Internet targets", set_internet_help: "Sites used by egress checks. Change them if the customer policy uses other objects.",
    set_json_help: "Advanced: edit the whole configuration as JSON.", apply_json: "Load JSON into the form", discard: "Discard changes", save: "Save",
    saved: "Saved.", none: "— none —",
    EXP: { ALLOW: "Allowed", BLOCK: "Blocked", INSPECTED: "Decrypted", NOT_INSPECTED: "Not decrypted", VALID: "Cert. valid", INVALID: "Cert. rejected",
      PRESERVED: "IP preserved", LIMITED: "Authorized only", MEASURE: "Measure", NO_FLOW: "No flow", MATRIX: "Per matrix" },
    ST: { OK: "OK", FAIL: "FAIL", ERROR: "ERROR", INFO: "INFO", SKIP: "N/A" },
    ROLES: { prod_envs: "Production environments (NET-07)", nonprod_envs: "Non-production environments (NET-07)", ids_target: "Target with Detect (IDS) profile (POL-15, IPS-11)",
      ids_clients: "Clients that run the IDS vs IPS comparison", ips_exception_client: "Asset with the IPS exception (IPS-04)", dlp_exception_client: "Asset with the DLP exception (DLP-02)",
      precedence_target: "Blocked target for rule precedence (POL-10)", precedence_clients: "Clients for rule precedence (POL-10)", perf_client: "Client that runs the performance measurements (PERF-*)" },
    NET: { allowed_site: "Allowed site (shares IP with the blocked FQDN)", allowed_business_site: "Allowed business site", blocked_fqdn: "Blocked FQDN (POL-05)",
      blocked_path: "Blocked path on the allowed site (APP-03)", geo_blocked_url: "URL in a geo-blocked country (IPS-08)", financial_site: "Financial site bypassed from HTTPS Inspection (TLS-05)",
      inspected_site: "Site that must be decrypted (TLS-02/05)", port_test_host: "Host answering on any TCP port", dns_resolver: "Public DNS resolver", exception_port: "Exception port between environments (POL-02)",
      c2_test_url: "Vendor C&C test URL (IPS-09, THR-05)", geo_blocked_countries: "Blocked countries (comma separated)", internal_cidr: "Internal range (summary)",
      ioc_test_domain: "Test domain for the IoC reaction (IPS-10)", inspection_ca_match: "Text in the TLS inspection CA name (empty = from the PEM)" },
  },
  es: {
    kicker: "Validación de seguridad", title: "Firewall Testkit", tab_tests: "Pruebas", tab_settings: "Configuración", tab_fwconfig: "Configuración del firewall",
    manual: "Manual", control: "agente de control", scope: "requiere infraestructura adicional", procedure: "Procedimiento", expected_res: "Resultado esperado", bp: "Buenas prácticas de Check Point",
    fw_title: "Configuración del firewall para las pruebas", fw_intro: "Lo que debe tener configurado el firewall probado para que las comprobaciones automáticas tengan sentido. Es neutral respecto al fabricante: aplícalo con las herramientas de cada solución. Cada caso indica además sus propios requisitos.",
    fw_cp: "Check Point: configuración base recomendada", fw_cp_intro: "Buenas prácticas de configuración de Check Point CloudGuard Network / Cloud Firewall. La carpeta checkpoint/ del kit aplica la configuración de pruebas por la API de gestión.",
    fw_cases: "Requisitos por caso", fw_manual: "Casos manuales", fw_manual_intro: "Casos que se validan siguiendo un procedimiento (consola, nube, integraciones). Ábrelos en la pestaña Pruebas para ver los pasos.",
    sol_none: "sin solución configurada (Configuración)", compare: "Comparar seleccionadas", compare_es: "ES", compare_help: "Marca dos o más ejecuciones para comparar soluciones.",
    set_solution: "Solución probada", set_solution_help: "Nombre que aparece en los informes y etiqueta las ejecuciones (p. ej. fabricante y producto). Cámbialo antes de probar otra solución.",
    sol_name: "Nombre de la solución", sol_vendor: "Fabricante", vendor_cp: "Check Point", vendor_other: "Otro",
    set_server: "Servidor de pruebas", set_server_help: "IP de workload del servidor de pruebas (se detecta sola). Si el servidor está en uno de los entornos, márcalo abajo.",
    col_cidr: "CIDR", add_agents: "Añadir clientes conectados",
    set_ca: "CA de inspección TLS", set_ca_help: "Certificado público (PEM) de la CA con la que la solución re-firma el TLS inspeccionado. Los clientes la añaden a su almacén de confianza y sirve para saber qué certificados se descifraron.",
    clients: "Clientes", no_clients: "Esperando clientes…", search: "Buscar caso o prueba (p. ej. TLS, EICAR, IPS-06)", run_sel: "Ejecutar selección",
    run_all: "Ejecutar todo", runs: "Ejecuciones", runs_help: "Elige una para ver sus resultados junto a cada prueba. Al terminar, descarga el informe en Word.",
    selected: (n) => `${n} pruebas seleccionadas`, run_case: "Ejecutar caso", objective: "Objetivo", requires: "Configuración necesaria en el firewall", how: "Notas de Check Point",
    evidence: "Evidencias", test: "Prueba", expected: "Esperado", result: "Resultado", informative: "informativa", ready: "listo", busy: "ocupado", offline: "sin conexión",
    no_runs: "Todavía no hay ejecuciones.", finished: "terminada", running: "en curso", report_en: "Informe EN", report_es: "Informe ES", fail: "fallo", info: "info", na: "n/a",
    no_match: "Ningún caso coincide con la búsqueda.", no_agent: "No hay ningún cliente conectado y seleccionado.",
    set_intro: "Describe la arquitectura del cliente: entornos y su IP de workload, cuál aloja el servidor de pruebas, la matriz permitida entre entornos y los papeles que usan algunas pruebas. Los agentes reciben esta configuración con cada ejecución.",
    set_envs: "Entornos", set_envs_help: "El nombre debe coincidir con TESTKIT_ENV del cliente de ese entorno. IP = IP de workload (la que atraviesa el firewall).",
    col_name: "Nombre", col_ip: "IP de workload", col_desc: "Descripción", col_server: "Servidor de pruebas", col_peer: "Par en otra AZ", add_env: "Añadir entorno",
    set_matrix: "Matriz de segmentación", set_matrix_help: "Servicios permitidos de cada origen (fila) a cada destino. Lo no marcado debe estar bloqueado.",
    always: "Permitido entre todos los entornos:", set_roles: "Papeles", set_roles_help: "Entornos que usan las pruebas que dependen de reglas concretas. Déjalo vacío para omitir esas pruebas.",
    set_internet: "Destinos en Internet", set_internet_help: "Sitios que usan las pruebas de salida. Cámbialos si la política del cliente usa otros objetos.",
    set_json_help: "Avanzado: edita toda la configuración en JSON.", apply_json: "Cargar el JSON en el formulario", discard: "Descartar cambios", save: "Guardar",
    saved: "Guardado.", none: "— ninguno —",
    EXP: { ALLOW: "Permitido", BLOCK: "Bloqueado", INSPECTED: "Descifrado", NOT_INSPECTED: "Sin descifrar", VALID: "Cert. válido", INVALID: "Cert. rechazado",
      PRESERVED: "IP conservada", LIMITED: "Solo autorizados", MEASURE: "Medida", NO_FLOW: "Sin flujo", MATRIX: "Según matriz" },
    ST: { OK: "OK", FAIL: "FALLO", ERROR: "ERROR", INFO: "INFO", SKIP: "N/A" },
    ROLES: { prod_envs: "Entornos de producción (NET-07)", nonprod_envs: "Entornos no productivos (NET-07)", ids_target: "Destino con perfil Detect/IDS (POL-15, IPS-11)",
      ids_clients: "Clientes que comparan IDS frente a IPS", ips_exception_client: "Activo con la excepción IPS (IPS-04)", dlp_exception_client: "Activo con la excepción DLP (DLP-02)",
      precedence_target: "Destino bloqueado para la precedencia (POL-10)", precedence_clients: "Clientes para la precedencia (POL-10)", perf_client: "Cliente que lanza las medidas de rendimiento (PERF-*)" },
    NET: { allowed_site: "Sitio permitido (comparte IP con el FQDN bloqueado)", allowed_business_site: "Sitio corporativo permitido", blocked_fqdn: "FQDN bloqueado (POL-05)",
      blocked_path: "Ruta bloqueada en el sitio permitido (APP-03)", geo_blocked_url: "URL en un país bloqueado (IPS-08)", financial_site: "Sitio financiero excluido de HTTPS Inspection (TLS-05)",
      inspected_site: "Sitio que debe descifrarse (TLS-02/05)", port_test_host: "Host que responde en cualquier puerto TCP", dns_resolver: "Resolvedor DNS público", exception_port: "Puerto de excepción entre entornos (POL-02)",
      c2_test_url: "URL de prueba de C&C del fabricante (IPS-09, THR-05)", geo_blocked_countries: "Países bloqueados (separados por comas)", internal_cidr: "Rango interno (resumen)",
      ioc_test_domain: "Dominio de prueba para la reacción a IoC (IPS-10)", inspection_ca_match: "Texto del nombre de la CA de inspección (vacío = del PEM)" },
  },
};
const MULTI_ROLES = ["prod_envs", "nonprod_envs", "ids_clients", "precedence_clients"];
const SERVICES = ["icmp", "http", "https", "ssh", "rdp", "tcp8080", "iperf3"];
let LANG = (() => { try { return localStorage.getItem("tk-lang") || (navigator.language || "en").slice(0, 2); } catch { return "en"; } })();
if (!I18N[LANG]) LANG = "en";
const t = (k) => I18N[LANG][k];
const tr = (x) => (x && typeof x === "object" ? x[LANG] || x.en : x);

let CAT, CONF, AGENTS = [], SEL_AGENTS = new Set(), RUN = null, RUN_ID = null, PCONF = null;
const CMP = new Set();
const isCP = () => /check ?point/i.test(((PCONF && PCONF.solution) || {}).vendor || "");
const sel = new Set();

// ------------------------------------------------------------------ i18n + tabs
function applyLang() {
  document.documentElement.lang = LANG;
  $$("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  $("#q").placeholder = t("search");
  const sol = ((PCONF && PCONF.solution) || {}).name;
  $(".kicker").textContent = t("kicker") + " · " + (sol || t("sol_none"));
  $$(".lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === LANG));
  if (CAT) { render(); pollRuns(); pollAgents(); }
  if (CONF && !$("#view-settings").hidden) renderSettings();
  if (CAT && !$("#view-fwconfig").hidden) renderFw();
}
$$(".lang button").forEach((b) => (b.onclick = () => { LANG = b.dataset.lang; try { localStorage.setItem("tk-lang", LANG); } catch {} applyLang(); }));
$$(".tab").forEach((b) => (b.onclick = () => {
  $$(".tab").forEach((x) => x.classList.toggle("on", x === b));
  $("#view-tests").hidden = b.dataset.tab !== "tests"; $("#view-settings").hidden = b.dataset.tab !== "settings"; $("#view-fwconfig").hidden = b.dataset.tab !== "fwconfig";
  if (b.dataset.tab === "settings") loadSettings();
  if (b.dataset.tab === "fwconfig") renderFw();
}));

// ------------------------------------------------------------------ tests view
async function init() {
  CAT = await api("catalog");
  try { PCONF = await api("config"); } catch { PCONF = {}; }
  applyLang();
  $("#q").oninput = render;
  $("#runall").onclick = () => launch([], t("run_all"));
  $("#runsel").onclick = () => launch([...sel]);
  setInterval(pollAgents, 4000); setInterval(pollRuns, 2500);
}

function render() {
  const q = $("#q").value.trim().toLowerCase(), box = $("#cases"), toc = $("#toc");
  const cases = CAT.cases.filter((c) => !q || (c.id + " " + tr(c.title) + " " + tr(c.how) + " " + c.checks.map((k) => k.id + " " + tr(k.name)).join(" ")).toLowerCase().includes(q));
  box.innerHTML = ""; toc.innerHTML = "";
  for (const d of CAT.domains) {
    const cs = cases.filter((c) => c.domain === d.id); if (!cs.length) continue;
    toc.insertAdjacentHTML("beforeend", `<a href="#d-${d.id}">${esc(d.id)} · ${esc(tr(d.name))}<span>${cs.length}</span></a>`);
    box.insertAdjacentHTML("beforeend", `<h2 class="dom" id="d-${d.id}">${esc(d.id)} · ${esc(tr(d.name))}</h2>`);
    cs.forEach((c) => box.appendChild(caseEl(c)));
  }
  if (!box.children.length) box.innerHTML = `<p class="muted">${t("no_match")}</p>`;
  paintResults(); updateSel();
}

function caseEl(c) {
  const el = $("#tpl-case").content.firstElementChild.cloneNode(true);
  el.dataset.case = c.id;
  $(".cid", el).textContent = c.id; $("h3", el).textContent = tr(c.title);
  const manual = c.mode === "manual", ctl = c.checks.some((k) => k.runner === "control");
  $(".badges", el).innerHTML = (c.scope ? `<span class="b scope">${t("scope")}</span>` : "") + (manual ? `<span class="b manual">${t("manual")}</span>` : "") +
    (ctl ? `<span class="b ctl">${t("control")}</span>` : "") + `<span class="b ${c.priority}">${esc(tr(c.priority_label))}</span>`;
  $(".h-obj", el).textContent = t("objective"); $(".obj", el).textContent = tr(c.objective);
  $(".h-req", el).textContent = t("requires"); $(".req", el).textContent = tr(c.requires);
  const notes = isCP() && c.vendor_notes && c.vendor_notes.checkpoint;
  $(".h-how", el).textContent = notes ? t("how") : ""; $(".how", el).textContent = notes ? tr(c.vendor_notes.checkpoint) : "";
  $(".evi", el).textContent = t("evidence") + ": " + tr(c.evidence);
  const bp = isCP() && c.bp_checkpoint; $(".h-bp", el).textContent = bp ? t("bp") : ""; $(".bp", el).textContent = bp ? tr(c.bp_checkpoint) : "";
  if (manual) {
    $(".manual", el).classList.add("on"); $(".h-proc", el).textContent = t("procedure"); $(".h-expd", el).textContent = t("expected_res");
    $(".steps", el).innerHTML = (c.procedure || []).map((s) => `<li>${esc(tr(s))}</li>`).join(""); $(".expd", el).textContent = tr(c.expected);
  }
  $(".th-test", el).textContent = t("test"); $(".th-exp", el).textContent = t("expected"); $(".th-res", el).textContent = t("result");
  const ck = $(".case-ck", el), rc = $(".run-case", el);
  rc.textContent = t("run_case"); if (manual) { rc.hidden = true; ck.parentElement.style.visibility = "hidden"; }
  ck.checked = c.checks.every((k) => sel.has(k.id));
  ck.onclick = (e) => { e.stopPropagation(); c.checks.forEach((k) => (ck.checked ? sel.add(k.id) : sel.delete(k.id))); $$(".chk", el).forEach((x) => (x.checked = ck.checked)); updateSel(); };
  rc.onclick = (e) => { e.stopPropagation(); launch([c.id], `${c.id} ${tr(c.title)}`); };
  $("header", el).onclick = () => el.classList.toggle("open");
  for (const k of c.checks) {
    const row = document.createElement("tr"); row.dataset.check = k.id;
    row.innerHTML = `<td><input type="checkbox" class="chk" ${sel.has(k.id) ? "checked" : ""}></td>
      <td class="n"><b>${esc(k.id)}</b> ${esc(tr(k.name))} ${k.informative ? `<span class="b">${t("informative")}</span>` : ""}${k.runner === "control" ? ` <span class="b ctl">${t("control")}</span>` : ""}<div class="ex">${esc(tr(k.explain))}</div><div class="bl">${esc(k.blade)}</div></td>
      <td>${esc(t("EXP")[k.expect] || k.expect)}</td><td class="res"><span class="muted small">—</span></td><td><button class="btn sm">▶</button></td>`;
    $(".chk", row).onchange = (e) => { e.target.checked ? sel.add(k.id) : sel.delete(k.id); updateSel(); };
    $("button", row).onclick = () => launch([k.id], `${k.id} ${tr(k.name)}`);
    $("tbody", el).appendChild(row);
  }
  return el;
}

function renderFw() {
  const g = CAT.config_guide || {}, li = (xs) => `<ol>${(xs || []).map((x) => `<li>${esc(tr(x))}</li>`).join("")}</ol>`;
  const auto = CAT.cases.filter((c) => c.mode !== "manual"), man = CAT.cases.filter((c) => c.mode === "manual");
  $("#fwconfig").innerHTML = `<section class="card fwc"><h2>${t("fw_title")}</h2><p class="muted small">${t("fw_intro")}</p>${li(g.firewall)}</section>` +
    (isCP() ? `<section class="card fwc"><h2>${t("fw_cp")}</h2><p class="muted small">${t("fw_cp_intro")}</p>${li(g.checkpoint)}</section>` : "") +
    `<section class="card fwc"><h2>${t("fw_cases")}</h2><table><tbody>${auto.map((c) => `<tr><td><b class="cid">${esc(c.id)}</b></td><td>${esc(tr(c.title))}</td><td>${esc(tr(c.requires))}${isCP() && c.bp_checkpoint ? `<div class="bp">${esc(tr(c.bp_checkpoint))}</div>` : ""}</td></tr>`).join("")}</tbody></table></section>` +
    `<section class="card fwc"><h2>${t("fw_manual")} (${man.length})</h2><p class="muted small">${t("fw_manual_intro")}</p><table><tbody>${man.map((c) => `<tr><td><b class="cid">${esc(c.id)}</b></td><td>${esc(tr(c.title))}${c.scope ? ` <span class="b scope">${t("scope")}</span>` : ""}</td><td>${esc(tr(c.requires))}</td></tr>`).join("")}</tbody></table></section>`;
}

function updateSel() { $("#selinfo").textContent = sel.size ? t("selected")(sel.size) : ""; $("#runsel").disabled = !sel.size; }

async function pollAgents() {
  try { AGENTS = await api("agents"); } catch { return; }
  const box = $("#agents");
  if (!AGENTS.length) { box.innerHTML = `<span class="muted">${t("no_clients")}</span>`; return; }
  if (!SEL_AGENTS.size) AGENTS.filter((a) => a.online).forEach((a) => SEL_AGENTS.add(a.name));
  box.innerHTML = AGENTS.map((a) => `<label class="chip ${a.online ? "on" : ""} ${a.busy ? "busy" : ""}" title="${esc(a.src || "")}">
    <input type="checkbox" data-a="${esc(a.name)}" ${SEL_AGENTS.has(a.name) ? "checked" : ""}><span class="dot"></span>${esc((a.env || a.name).toUpperCase())}
    <small>${a.online ? (a.busy ? t("busy") : t("ready")) : t("offline")}</small></label>`).join("");
  $$("input", box).forEach((i) => (i.onchange = () => (i.checked ? SEL_AGENTS.add(i.dataset.a) : SEL_AGENTS.delete(i.dataset.a))));
}

async function launch(ids, label) {
  const agents = [...SEL_AGENTS].filter((n) => AGENTS.find((a) => a.name === n && a.online));
  if (!agents.length) return alert(t("no_agent"));
  const r = await api("runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids, agents, label }) });
  RUN_ID = r.id; pollRuns();
}

async function pollRuns() {
  let runs; try { runs = await api("runs"); } catch { return; }
  if (!RUN_ID && runs.length) RUN_ID = runs[0].id;
  $("#runs").innerHTML = runs.map((r) => {
    const c = r.counts, done = Object.values(r.status).every((s) => s === "done");
    return `<div class="run ${r.id === RUN_ID ? "sel" : ""}" data-id="${r.id}"><div class="t"><input type="checkbox" class="cmp" data-id="${r.id}" ${CMP.has(r.id) ? "checked" : ""}> ${esc(r.solution || "")} · ${esc(r.label)}</div>
      <div class="m">${r.created.replace("T", " ").replace("Z", " UTC")} · ${r.agents.map((a) => a.toUpperCase()).join(", ")} · ${done ? t("finished") : t("running")}</div>
      <div><span class="pill OK">${c.OK} OK</span><span class="pill FAIL">${c.FAIL + c.ERROR} ${t("fail")}</span><span class="pill INFO">${c.INFO} ${t("info")}</span><span class="pill SKIP">${c.SKIP} ${t("na")}</span></div>
      <div class="dl"><a class="btn sm" href="api/runs/${r.id}/report?lang=en">${t("report_en")}</a><a class="btn sm" href="api/runs/${r.id}/report?lang=es">${t("report_es")}</a><a class="btn sm" href="api/runs/${r.id}/csv">CSV</a></div></div>`;
  }).join("") || `<p class="muted small">${t("no_runs")}</p>`;
  const ids = [...CMP].join(",");
  $("#cmpbar").innerHTML = `<span class="muted small">${t("compare_help")}</span><div class="dl"><a class="btn sm ${CMP.size < 2 ? "dis" : ""}" href="api/compare?runs=${ids}&lang=en">${t("compare")} EN</a><a class="btn sm ${CMP.size < 2 ? "dis" : ""}" href="api/compare?runs=${ids}&lang=es">${t("compare_es")}</a></div>`;
  $$(".cmp", $("#runs")).forEach((c) => (c.onclick = (e) => { e.stopPropagation(); c.checked ? CMP.add(c.dataset.id) : CMP.delete(c.dataset.id); pollRuns(); }));
  $$(".run", $("#runs")).forEach((el) => (el.onclick = (e) => { if (e.target.tagName === "A" || e.target.tagName === "INPUT") return; RUN_ID = el.dataset.id; pollRuns(); }));
  if (RUN_ID) { try { RUN = await api("runs/" + RUN_ID); } catch { RUN = null; } paintResults(); }
}

function paintResults() {
  $$("tr[data-check] .res").forEach((td) => (td.innerHTML = '<span class="muted small">—</span>'));
  if (!RUN) return;
  const ST = t("ST"), by = {};
  for (const [name, a] of Object.entries(RUN.agents)) for (const r of a.results) {
    const base = r.id.split(".").slice(0, 2).join(".");
    (by[base] = by[base] || []).push({ ...r, agent: name });
  }
  const multi = Object.keys(RUN.agents).length > 1;
  for (const [id, list] of Object.entries(by)) {
    const td = document.querySelector(`tr[data-check="${CSS.escape(id)}"] .res`); if (!td) continue;
    if (list.some((r) => r.id !== id)) {   // segmentation matrix: summary per agent
      const g = {}; list.forEach((r) => { g[r.agent] = g[r.agent] || { OK: 0, n: 0, F: 0 }; g[r.agent].n++; if (r.status === "OK") g[r.agent].OK++; if (r.status === "FAIL" || r.status === "ERROR") g[r.agent].F++; });
      td.innerHTML = Object.entries(g).map(([a, v]) => `<span class="pill ${v.F ? "FAIL" : "OK"}">${a.toUpperCase()} ${v.OK}/${v.n}</span>`).join("") +
        `<div class="det">${list.filter((r) => r.status === "FAIL").map((r) => esc(r.name) + ": " + esc(r.observed)).join("; ")}</div>`;
    } else {
      const shown = list.find((r) => r.status !== "SKIP") || list[0];
      td.innerHTML = list.map((r) => `<span class="pill ${r.status}" title="${esc(r.detail)}">${multi ? r.agent.toUpperCase() + " " : ""}${ST[r.status]}</span>`).join("") + `<div class="det">${esc(shown.detail)}</div>`;
    }
  }
  for (const [name, a] of Object.entries(RUN.agents)) if (a.status !== "done") {
    $$("tr[data-check]").forEach((row) => {
      const wanted = !RUN.ids.length || RUN.ids.some((i) => row.dataset.check === i || row.dataset.check.startsWith(i + "."));
      const td = $(".res", row); if (wanted && td.textContent === "—") td.innerHTML = `<span class="pill RUN">${name.toUpperCase()} …</span>`;
    });
  }
}

// ------------------------------------------------------------------ settings view
async function loadSettings() { CONF = await api("config"); delete CONF._server_ip; renderSettings(); }

function envNames() { return (CONF.environments || []).map((e) => e.name).filter(Boolean); }
function opts(cur_, multi) {
  const names = envNames(), cur = multi ? cur_ || [] : [cur_ || ""];
  return (multi ? "" : `<option value="">${t("none")}</option>`) + names.map((n) => `<option ${cur.includes(n) ? "selected" : ""}>${esc(n)}</option>`).join("");
}

function renderSettings() {
  CONF.solution = CONF.solution || { name: "", vendor: "" };
  const sv = /check ?point/i.test(CONF.solution.vendor || "") ? "checkpoint" : "other";
  $("#solution").innerHTML = `<label><span>${t("sol_name")}</span><input id="solname" value="${esc(CONF.solution.name)}"></label>
    <label><span>${t("sol_vendor")}</span><select id="solvendor"><option value="checkpoint" ${sv === "checkpoint" ? "selected" : ""}>${t("vendor_cp")}</option><option value="other" ${sv === "other" ? "selected" : ""}>${t("vendor_other")}</option></select></label>`;
  $("#solname").onchange = (e) => { CONF.solution.name = e.target.value.trim(); syncJson(); };
  $("#solvendor").onchange = (e) => { CONF.solution.vendor = e.target.value === "checkpoint" ? "checkpoint" : ""; syncJson(); };
  $("#server").innerHTML = `<label><span>IP</span><input id="srvip" value="${esc(CONF.server_ip || "")}" placeholder="10.0.0.10"></label>`;
  $("#srvip").onchange = (e) => { CONF.server_ip = e.target.value.trim(); syncJson(); };
  $("#capem").value = CONF.inspection_ca_pem || "";
  $("#capem").onchange = (e) => { CONF.inspection_ca_pem = e.target.value.trim() ? e.target.value.trim() + "\n" : ""; syncJson(); };
  $("#addagents").onclick = async () => {
    const ag = await api("agents");
    for (const a of ag) if (a.online && !CONF.environments.some((e) => e.name === (a.env || a.name)))
      CONF.environments.push({ name: a.env || a.name, ip: a.src || "", cidr: "", az: "", description: "" });
    renderSettings();
  };
  CONF.environments = CONF.environments || []; CONF.roles = CONF.roles || {}; CONF.peers = CONF.peers || {}; CONF.internet = CONF.internet || {};
  CONF.segmentation = CONF.segmentation || { allow: {}, always: [] }; CONF.segmentation.allow = CONF.segmentation.allow || {}; CONF.segmentation.always = CONF.segmentation.always || [];
  const tb = $("#envs tbody");
  tb.innerHTML = CONF.environments.map((e, i) => `<tr data-i="${i}">
    <td><input data-f="name" value="${esc(e.name)}"></td><td><input data-f="ip" value="${esc(e.ip)}" placeholder="10.0.0.10"></td><td><input data-f="cidr" value="${esc(e.cidr || "")}" placeholder="10.0.0.0/16"></td>
    <td><input data-f="az" value="${esc(e.az || "")}" size="3"></td><td><input data-f="description" value="${esc(e.description || "")}"></td>
    <td class="c"><input type="radio" name="srv" ${CONF.server_env === e.name ? "checked" : ""}></td>
    <td><select data-peer>${opts(CONF.peers[e.name], false)}</select></td><td><button class="btn sm del">✕</button></td></tr>`).join("");
  $$("tr", tb).forEach((row) => {
    const i = +row.dataset.i, e = CONF.environments[i];
    $$("input[data-f]", row).forEach((inp) => (inp.onchange = () => {
      const old = e.name; e[inp.dataset.f] = inp.value.trim();
      if (inp.dataset.f === "name" && old !== e.name) renameEnv(old, e.name);
      renderSettings();
    }));
    $("input[type=radio]", row).onchange = () => { CONF.server_env = e.name; syncJson(); };
    $("select[data-peer]", row).onchange = (ev) => { ev.target.value ? (CONF.peers[e.name] = ev.target.value) : delete CONF.peers[e.name]; syncJson(); };
    $(".del", row).onclick = () => { CONF.environments.splice(i, 1); renderSettings(); };
  });
  $("#addenv").onclick = () => { CONF.environments.push({ name: "env" + (CONF.environments.length + 1), ip: "", az: "", description: "" }); renderSettings(); };

  const names = envNames();
  let m = `<table class="grid matrix"><thead><tr><th></th>${names.map((n) => `<th>→ ${esc(n.toUpperCase())}</th>`).join("")}</tr></thead><tbody>`;
  for (const s of names) {
    m += `<tr><th>${esc(s.toUpperCase())}</th>` + names.map((d) => s === d ? `<td class="self">—</td>` :
      `<td>${SERVICES.filter((x) => !CONF.segmentation.always.includes(x)).map((x) => `<label class="svc"><input type="checkbox" data-pair="${esc(s)}>${esc(d)}" data-svc="${x}" ${(CONF.segmentation.allow[`${s}>${d}`] || []).includes(x) ? "checked" : ""}>${x}</label>`).join("")}</td>`).join("") + "</tr>";
  }
  $("#matrix").innerHTML = m + "</tbody></table>";
  $$("#matrix input").forEach((i) => (i.onchange = () => {
    const a = new Set(CONF.segmentation.allow[i.dataset.pair] || []); i.checked ? a.add(i.dataset.svc) : a.delete(i.dataset.svc);
    a.size ? (CONF.segmentation.allow[i.dataset.pair] = [...a]) : delete CONF.segmentation.allow[i.dataset.pair]; syncJson();
  }));
  $("#always").innerHTML = SERVICES.map((x) => `<label class="svc"><input type="checkbox" data-always="${x}" ${CONF.segmentation.always.includes(x) ? "checked" : ""}>${x}</label>`).join("");
  $$("#always input").forEach((i) => (i.onchange = () => {
    const a = new Set(CONF.segmentation.always); i.checked ? a.add(i.dataset.always) : a.delete(i.dataset.always); CONF.segmentation.always = [...a]; renderSettings();
  }));

  $("#roles").innerHTML = Object.entries(t("ROLES")).map(([k, l]) => `<label><span>${esc(l)}</span><select data-role="${k}" ${MULTI_ROLES.includes(k) ? "multiple" : ""}>${opts(CONF.roles[k], MULTI_ROLES.includes(k))}</select></label>`).join("");
  $$("#roles select").forEach((s) => (s.onchange = () => {
    const k = s.dataset.role; CONF.roles[k] = MULTI_ROLES.includes(k) ? [...s.selectedOptions].map((o) => o.value) : s.value; syncJson();
  }));
  $("#internet").innerHTML = Object.entries(t("NET")).map(([k, l]) => {
    const v = k === "inspection_ca_match" ? CONF.inspection_ca_match : k === "internal_cidr" ? CONF.internal_cidr : k === "geo_blocked_countries" ? (CONF.internet[k] || []).join(", ") : CONF.internet[k];
    return `<label><span>${esc(l)}</span><input data-net="${k}" value="${esc(v ?? "")}"></label>`;
  }).join("");
  $$("#internet input").forEach((i) => (i.onchange = () => {
    const k = i.dataset.net, v = i.value.trim();
    if (k === "inspection_ca_match") CONF.inspection_ca_match = v;
    else if (k === "internal_cidr") CONF.internal_cidr = v;
    else if (k === "geo_blocked_countries") CONF.internet[k] = v.split(",").map((x) => x.trim()).filter(Boolean);
    else CONF.internet[k] = k === "exception_port" && /^\d+$/.test(v) ? +v : v;
    syncJson();
  }));
  syncJson();
  $("#applyjson").onclick = () => { try { CONF = JSON.parse($("#json").value); renderSettings(); $("#savemsg").textContent = ""; } catch (e) { $("#savemsg").textContent = e.message; } };
  $("#reload").onclick = loadSettings;
  $("#save").onclick = async () => {
    try { await api("config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(CONF) }); $("#savemsg").textContent = t("saved"); PCONF = JSON.parse(JSON.stringify(CONF)); applyLang(); }
    catch (e) { $("#savemsg").textContent = e.message; }
  };
}

function renameEnv(old, nw) {
  if (CONF.server_env === old) CONF.server_env = nw;
  for (const [k, v] of Object.entries(CONF.roles)) CONF.roles[k] = Array.isArray(v) ? v.map((x) => (x === old ? nw : x)) : v === old ? nw : v;
  const peers = {}; for (const [k, v] of Object.entries(CONF.peers)) peers[k === old ? nw : k] = v === old ? nw : v; CONF.peers = peers;
  const allow = {}; for (const [k, v] of Object.entries(CONF.segmentation.allow)) { const [a, b] = k.split(">"); allow[`${a === old ? nw : a}>${b === old ? nw : b}`] = v; } CONF.segmentation.allow = allow;
}
function syncJson() { $("#json").value = JSON.stringify(CONF, null, 1); }

init();
