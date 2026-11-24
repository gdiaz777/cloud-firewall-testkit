// Word report of a portal run.  node report.js <run.json> <tests.json> <workdir with PNGs> <out.docx> [en|es]
const fs = require("fs");
const path = require("path");
const L = require("./lib");
const [runF, catF, work, outF, langArg] = process.argv.slice(2);
const LANG = langArg === "es" ? "es" : "en";
const run = JSON.parse(fs.readFileSync(runF, "utf8"));
const cat = JSON.parse(fs.readFileSync(catF, "utf8"));
const img = (f) => path.join(work, f);
const has = (f) => fs.existsSync(img(f));
const tr = (x) => (x && typeof x === "object" ? x[LANG] || x.en : x || "");

const T = {
  en: {
    kicker: "FIREWALL TESTKIT · SECURITY VALIDATION", title: "Security test report", footer: "Firewall Testkit · Confidential · Page ",
    subtitle: (s) => `Results of the security checks against ${s}`, contents: "Contents", solution: "Solution under test",
    run: "Run", date: "Date", clients: "Test clients", server: "Server",
    s1: "Executive summary",
    lead: (n, c, who, ok, ev, info) => `**${n} automated checks** of **${c} test cases** were run from ${who}. **${ok} of ${ev}** returned the expected result${info ? ` and ${info} are measurements or informative checks` : ""}.`,
    k_exp: "Expected result", k_cases: "Cases passing", k_https: "Checks over HTTPS", k_bad: "Unexpected results",
    f1: "Figure 1. Overall result.", f2: "Figure 2. Result by domain.", f3: "Figure 3. Checks by security capability.", f4: "Figure 4. Attacks and content blocked over HTTP and inside HTTPS.",
    case: "Case", test: "Test", result: "Result", checks: "Checks", measure: "measure", unexpected: "Unexpected results",
    unexpected_line: (r, exp, obs) => `**${r.id}** ${r.name} (${r.agent.toUpperCase()}): expected ${exp}, observed ${obs}. ${r.detail}`,
    s2: "How it was tested",
    method: "The kit is two Docker containers: a **server** that publishes test content over HTTP and HTTPS (EICAR, benign files, synthetic data, services on unauthorized ports) plus this portal, and one or more **clients** (agents) in the environments. Every check leaves from the client's workload IP, crosses the firewall and reaches the server or the Internet.",
    legend: ["**Allowed / Blocked**: blocked means reset or dropped connection, or a block page of the solution under test.",
      "**Decrypted / Not decrypted**: the issuer of the received certificate is (or is not) the TLS inspection CA of the solution under test.",
      "**Measure**: characterization checks (MTU, HTTPS Inspection overhead) without a pass threshold.",
      "**Informative**: classes the catalog assigns to a WAF; run to document IPS coverage.",
      "**Not applicable**: the check does not apply to that client (e.g., from the server environment to itself, or not configured).",
      "**Control agent (CONTROL)**: operator-side checks through the cloud and management APIs (high availability, logs, policy, operations); during failovers every client probes continuously.",
      "**Meets criterion / Does not meet**: result of a check with an explicit acceptance criterion stated in its detail."],
    asked: "Objective.", how: "Check Point notes.", req: "Firewall configuration needed.", bp: "Check Point best practice.",
    manual_s: "Manual procedures", manual_intro: (n) => `${n} cases of the catalog are validated by following a procedure (management and cloud consoles, integrations, costs). They are listed here with their steps, expected result and evidence so they can be run and recorded.`,
    manual_line: (n) => `**${n} manual cases** are described with their procedure in the "Manual procedures" chapter.`, proc: "Procedure.", expd: "Expected result.", evi: "Evidence.",
    scope: "Needs infrastructure beyond the reference environment.", fwc: "Annex: firewall configuration", fwc_intro: "Configuration the firewall under test must have so the automated checks are meaningful (vendor-neutral).",
    fwc_cp: "Check Point recommended baseline",
    arch: "Figure. Tested architecture (from the portal settings).", ha_s: "High availability", ha_intro: "During every failover event (control agent) each client probes the server, the Internet and a denied flow once per second and keeps long sessions open. The charts summarise the interruptions and the replacement of a failed gateway; the case tables below have the detail.",
    ha_f1: "Figure. Longest continuous interruption per client.", ha_f2: "Figure. Timeline of the automatic replacement of a gateway.",
    perf_s: "Performance", perf_intro: "Measured from one client to the test server through the solution. They are lower bounds of the deployment (also limited by the test instances), not the maximum of the solution.",
    pf1: "Figure. Throughput with access control only (grey) and with the full inspection profile (red).", pf2: "Figure. Latency p50/p95/p99.", pf3: "Figure. Packets per second and loss with UDP.",
    c_id: "#", c_check: "Check", c_client: "Client", c_exp: "Expected", c_obs: "Observed", c_res: "Result", c_det: "Detail",
    annex: "Annex: run data", field: "Field", value: "Value", start: "Start", client: "Client", envs: "Environments", catalog: "Catalog",
    catline: (n, k) => `${n} cases, ${k} automated checks`, notfinished: "not finished",
    logs: "Each check can be found in the firewall logs (Logs & Monitor) by filtering on the client's source IP and the start time in the run CSV.",
    ST: { OK: "Pass", FAIL: "Fail", ERROR: "Fail", INFO: "Measure", SKIP: "Not applicable" }, V: { Cumple: "Pass", Parcial: "Partial", "No cumple": "Fail", Medida: "Measure" },
    EXP: { ALLOW: "Allowed", BLOCK: "Blocked", INSPECTED: "Decrypted", NOT_INSPECTED: "Not decrypted", VALID: "Cert. valid", INVALID: "Cert. rejected", PRESERVED: "IP preserved",
      CHANGED: "IP changed", LIMITED: "Authorized only", EXPOSED: "Exposed", MEASURE: "Measure", NO_FLOW: "No flow", FLOW: "Flow", ERROR: "Error", PASS: "Criterion met", NOT_MET: "Criterion not met", "-": "—" },
  },
  es: {
    kicker: "FIREWALL TESTKIT · VALIDACIÓN DE SEGURIDAD", title: "Informe de pruebas de seguridad", footer: "Firewall Testkit · Confidencial · Página ",
    subtitle: (s) => `Resultados de las pruebas de seguridad sobre ${s}`, contents: "Contenido", solution: "Solución probada",
    run: "Ejecución", date: "Fecha", clients: "Clientes de prueba", server: "Servidor",
    s1: "Resumen ejecutivo",
    lead: (n, c, who, ok, ev, info) => `Se ejecutaron **${n} comprobaciones automáticas** de **${c} casos de prueba** desde ${who}. **${ok} de ${ev}** dieron el resultado esperado${info ? ` y ${info} son medidas o pruebas informativas` : ""}.`,
    k_exp: "Resultado esperado", k_cases: "Casos que cumplen", k_https: "Pruebas sobre HTTPS", k_bad: "Resultados no esperados",
    f1: "Figura 1. Resultado global.", f2: "Figura 2. Resultado por dominio.", f3: "Figura 3. Comprobaciones por capacidad de seguridad.", f4: "Figura 4. Ataques y contenidos bloqueados por HTTP y dentro de HTTPS.",
    case: "Caso", test: "Prueba", result: "Resultado", checks: "Comprobaciones", measure: "medida", unexpected: "Resultados no esperados",
    unexpected_line: (r, exp, obs) => `**${r.id}** ${r.name} (${r.agent.toUpperCase()}): esperado ${exp}, observado ${obs}. ${r.detail}`,
    s2: "Cómo se ha probado",
    method: "El kit son dos contenedores Docker: un **servidor** que publica contenido de prueba por HTTP y HTTPS (EICAR, ficheros benignos, datos sintéticos, servicios en puertos no autorizados) y este portal, y uno o varios **clientes** (agentes) en los entornos. Cada comprobación sale de la IP de workload del cliente, atraviesa el firewall y llega al servidor o a Internet.",
    legend: ["**Permitido / Bloqueado**: bloqueado significa conexión reiniciada o descartada, o página de bloqueo de la solución probada.",
      "**Descifrado / Sin descifrar**: el emisor del certificado recibido es (o no) la CA de inspección TLS de la solución probada.",
      "**Medida**: pruebas de caracterización (MTU, sobrecoste de HTTPS Inspection) sin umbral de aprobado.",
      "**Informativa**: clases que el catálogo atribuye a un WAF; se ejecutan para documentar la cobertura del IPS.",
      "**No aplica**: la comprobación no corresponde a ese cliente (por ejemplo, desde el entorno del servidor hacia sí mismo, o sin configurar).",
      "**Agente de control (CONTROL)**: comprobaciones del lado del operador por las API de la nube y de la gestión (alta disponibilidad, registros, política, operación); durante los failovers todos los clientes sondean de forma continua.",
      "**Cumple criterio / No cumple criterio**: resultado de una comprobación con un criterio de aceptación explícito, indicado en su detalle."],
    asked: "Objetivo.", how: "Notas de Check Point.", req: "Configuración necesaria en el firewall.", bp: "Buena práctica de Check Point.",
    manual_s: "Procedimientos manuales", manual_intro: (n) => `${n} casos del catálogo se validan siguiendo un procedimiento (consolas de gestión y de la nube, integraciones, costes). Se recogen aquí con sus pasos, el resultado esperado y las evidencias para ejecutarlos y registrarlos.`,
    manual_line: (n) => `**${n} casos manuales** se describen con su procedimiento en el capítulo «Procedimientos manuales».`, proc: "Procedimiento.", expd: "Resultado esperado.", evi: "Evidencias.",
    scope: "Requiere infraestructura adicional al entorno de referencia.", fwc: "Anexo: configuración del firewall", fwc_intro: "Configuración que debe tener el firewall probado para que las comprobaciones automáticas tengan sentido (neutral respecto al fabricante).",
    fwc_cp: "Configuración base recomendada de Check Point",
    arch: "Figura. Arquitectura probada (según la configuración del portal).", ha_s: "Alta disponibilidad", ha_intro: "Durante cada evento de failover (agente de control) cada cliente sondea cada segundo el servidor, Internet y un flujo denegado, y mantiene sesiones largas abiertas. Las gráficas resumen las interrupciones y la sustitución de un gateway caído; el detalle está en las tablas de cada caso.",
    ha_f1: "Figura. Interrupción continua más larga por cliente.", ha_f2: "Figura. Cronología de la sustitución automática de un gateway.",
    perf_s: "Rendimiento", perf_intro: "Medido desde un cliente hacia el servidor de pruebas a través de la solución. Son mínimos del despliegue (limitados también por las instancias de prueba), no el máximo de la solución.",
    pf1: "Figura. Caudal solo con control de acceso (gris) y con el perfil completo de inspección (rojo).", pf2: "Figura. Latencia p50/p95/p99.", pf3: "Figura. Paquetes por segundo y pérdida con UDP.",
    c_id: "#", c_check: "Comprobación", c_client: "Cliente", c_exp: "Esperado", c_obs: "Observado", c_res: "Resultado", c_det: "Detalle",
    annex: "Anexo: datos de la ejecución", field: "Campo", value: "Valor", start: "Inicio", client: "Cliente", envs: "Entornos", catalog: "Catálogo",
    catline: (n, k) => `${n} casos, ${k} comprobaciones automáticas`, notfinished: "sin terminar",
    logs: "Cada comprobación se localiza en los registros del firewall (Logs & Monitor) filtrando por la IP de origen del cliente y la hora de inicio que figura en el CSV de la ejecución.",
    ST: { OK: "Cumple", FAIL: "No cumple", ERROR: "No cumple", INFO: "Medida", SKIP: "No aplica" }, V: { Cumple: "Cumple", Parcial: "Parcial", "No cumple": "No cumple", Medida: "Medida" },
    EXP: { ALLOW: "Permitido", BLOCK: "Bloqueado", INSPECTED: "Descifrado", NOT_INSPECTED: "Sin descifrar", VALID: "Cert. válido", INVALID: "Cert. rechazado", PRESERVED: "IP conservada",
      CHANGED: "IP cambiada", LIMITED: "Solo autorizados", EXPOSED: "Expuesto", MEASURE: "Medida", NO_FLOW: "Sin flujo", FLOW: "Con flujo", ERROR: "Error", PASS: "Cumple criterio", NOT_MET: "No cumple criterio", "-": "—" },
  },
}[LANG];

const fmtDate = (iso) => new Date(iso).toLocaleString(LANG === "es" ? "es-ES" : "en-GB", { dateStyle: "long", timeStyle: "short", timeZone: "UTC" }) + " UTC";
const casesById = Object.fromEntries(cat.cases.map((c) => [c.id, c]));
const checkName = {}; cat.cases.forEach((c) => c.checks.forEach((k) => (checkName[k.id] = tr(k.name))));
const results = Object.entries(run.agents).flatMap(([a, ag]) => ag.results.map((r) => ({ ...r, agent: a, name: checkName[r.id] || r.name })));
const exec = results.filter((r) => r.status !== "SKIP");
const cnt = (f) => exec.filter(f).length;
const ok = cnt((r) => r.status === "OK"), bad = cnt((r) => r.status === "FAIL" || r.status === "ERROR"), info = cnt((r) => r.status === "INFO");
const httpsBlock = exec.filter((r) => (r.blade || "").includes("TLS inspection") && r.status !== "INFO");
const httpsOk = httpsBlock.filter((r) => r.status === "OK").length;
const caseIds = cat.cases.map((c) => c.id).filter((id) => exec.some((r) => r.case === id));
const verdict = (id) => {
  const rs = exec.filter((r) => r.case === id && r.status !== "INFO");
  if (!rs.length) return "Medida";
  const f = rs.filter((r) => r.status !== "OK").length;
  return f === 0 ? "Cumple" : f === rs.length ? "No cumple" : "Parcial";
};
const verdicts = caseIds.map(verdict);
const who = Object.entries(run.agents).map(([n, a]) => `${(a.env || n).toUpperCase()} (${a.src || "?"})`).join(", ");
const manualCases = cat.cases.filter((c) => c.mode === "manual" && (!(run.ids || []).length || run.ids.includes(c.id)));
const cfg = run.config || {};
const SOL = (typeof run.solution === "string" && run.solution) || (cfg.solution || {}).name || (LANG === "es" ? "la solución probada" : "the solution under test");
const isCP = /check ?point/i.test(((cfg.solution || {}).vendor || "") + " " + SOL);
const srvIp = cfg.server_ip || (cfg.environments || []).find((e) => e.name === cfg.server_env)?.ip || "";

const children = [
  ...L.cover({ kicker: T.kicker, title: T.title, subtitle: T.subtitle(SOL), meta: [[T.solution, SOL], [T.run, `${run.label} · ${run.id}`], [T.date, fmtDate(run.created)], [T.clients, who], [T.server, srvIp]] }),
  ...L.toc(T.contents),
  L.H1(`1. ${T.s1}`),
  L.P(T.lead(exec.length, caseIds.length, who, ok, ok + bad, info)),
  ...(manualCases.length ? [L.P(T.manual_line(manualCases.length))] : []),
  L.kpis([
    { v: `${ok}/${ok + bad}`, l: T.k_exp, s: bad ? "Parcial" : "OK" },
    { v: `${verdicts.filter((v) => v === "Cumple").length}/${verdicts.filter((v) => v !== "Medida").length}`, l: T.k_cases, s: verdicts.includes("No cumple") || verdicts.includes("Parcial") ? "Parcial" : "OK" },
    { v: httpsBlock.length ? `${httpsOk}/${httpsBlock.length}` : "—", l: T.k_https, s: httpsOk === httpsBlock.length ? "OK" : "Parcial" },
    { v: String(bad), l: T.k_bad, s: bad ? "No cumple" : "OK" },
  ]),
  L.spacer(160),
  ...(has("summary.png") ? [L.image(img("summary.png"), 430), L.caption(T.f1)] : []),
  ...(has("domains.png") ? [L.image(img("domains.png"), 600), L.caption(T.f2)] : []),
  L.table([{ h: T.case, w: 0.8 }, { h: T.test, w: 3 }, { h: T.result, w: 0.9, status: true }, { h: T.checks, w: 1, align: "center" }],
    caseIds.map((id) => {
      const rs = exec.filter((r) => r.case === id), m = rs.filter((r) => r.status === "INFO").length;
      return [id, tr(casesById[id]?.title), T.V[verdict(id)], `${rs.filter((r) => r.status === "OK").length}/${rs.length - m}` + (m ? ` + ${m} ${T.measure}` : "")];
    })),
  ...(bad ? [L.spacer(), L.callout(T.unexpected, exec.filter((r) => r.status === "FAIL" || r.status === "ERROR").map((r) => T.unexpected_line(r, T.EXP[r.expect] || r.expect, T.EXP[r.observed] || r.observed)), "warn")] : []),
  L.H1(`2. ${T.s2}`),
  L.P(T.method),
  ...T.legend.map((x) => L.bullet(x)),
  ...(has("blades.png") ? [L.image(img("blades.png"), 580), L.caption(T.f3)] : []),
  ...(has("https.png") ? [L.image(img("https.png"), 480), L.caption(T.f4)] : []),
  ...(has("architecture.png") ? [L.image(img("architecture.png"), 620), L.caption(T.arch)] : []),
];

let n = 3;
if (has("ha_outage.png") || has("ha_timeline.png")) {
  children.push(L.H1(`${n++}. ${T.ha_s}`), L.P(T.ha_intro));
  if (has("ha_outage.png")) children.push(L.image(img("ha_outage.png"), 600), L.caption(T.ha_f1));
  if (has("ha_timeline.png")) children.push(L.image(img("ha_timeline.png"), 600), L.caption(T.ha_f2));
}
if (has("perf_throughput.png") || has("perf_latency.png")) {
  children.push(L.H1(`${n++}. ${T.perf_s}`), L.P(T.perf_intro));
  if (has("perf_throughput.png")) children.push(L.image(img("perf_throughput.png"), 600), L.caption(T.pf1));
  if (has("perf_latency.png")) children.push(L.image(img("perf_latency.png"), 520), L.caption(T.pf2));
  if (has("perf_udp.png")) children.push(L.image(img("perf_udp.png"), 520), L.caption(T.pf3));
}
const multi = Object.keys(run.agents).length > 1;
for (const d of cat.domains) {
  const ids = caseIds.filter((id) => id.startsWith(d.id + "-"));
  if (!ids.length) continue;
  children.push(L.H1(`${n++}. ${d.id} · ${tr(d.name)}`));
  for (const id of ids) {
    const c = casesById[id];
    children.push(L.H2(`${id} · ${tr(c.title)}`));
    children.push(L.P(`**${T.asked}** ${tr(c.objective)}`));
    if (isCP && c.vendor_notes && c.vendor_notes.checkpoint) children.push(L.P(`**${T.how}** ${tr(c.vendor_notes.checkpoint)}`));
    children.push(L.P(`**${T.req}** ${tr(c.requires)}`, { color: "4B5563" }));
    if (isCP && c.bp_checkpoint) children.push(L.P(`**${T.bp}** ${tr(c.bp_checkpoint)}`, { color: "5B21B6" }));
    const cols = [{ h: T.c_id, w: 0.45 }, { h: T.c_check, w: 2.3 }, ...(multi ? [{ h: T.c_client, w: 0.75 }] : []), { h: T.c_exp, w: 1.05 }, { h: T.c_obs, w: 1.05 }, { h: T.c_res, w: 1, status: true }, { h: T.c_det, w: 2.8 }];
    children.push(L.table(cols, results.filter((r) => r.case === id).map((r) => [r.id.replace(id + ".", ""), r.name, ...(multi ? [(r.env || r.agent).toUpperCase()] : []),
      T.EXP[r.expect] || r.expect, T.EXP[r.observed] || r.observed, T.ST[r.status], r.detail])));
    children.push(L.spacer(80));
  }
}

if (manualCases.length) {
  children.push(L.H1(`${n++}. ${T.manual_s}`));
  children.push(L.P(T.manual_intro(manualCases.length)));
  let inst = 1;
  for (const d of cat.domains) {
    const cs = manualCases.filter((c) => c.domain === d.id);
    if (!cs.length) continue;
    for (const c of cs) {
      children.push(L.H2(`${c.id} · ${tr(c.title)}`));
      children.push(L.P(`**${T.asked}** ${tr(c.objective)}`));
      children.push(L.P(`**${T.req}** ${tr(c.requires)}`, { color: "4B5563" }));
      if (c.scope) children.push(L.P(T.scope, { color: "6B7280" }));
      children.push(L.P(`**${T.proc}**`));
      inst++; (c.procedure || []).forEach((st) => children.push(L.numbered(tr(st), inst)));
      children.push(L.P(`**${T.expd}** ${tr(c.expected)}`));
      children.push(L.P(`**${T.evi}** ${tr(c.evidence)}`, { color: "4B5563" }));
      if (isCP && c.vendor_notes && c.vendor_notes.checkpoint) children.push(L.P(`**${T.how}** ${tr(c.vendor_notes.checkpoint)}`));
      if (isCP && c.bp_checkpoint) children.push(L.P(`**${T.bp}** ${tr(c.bp_checkpoint)}`, { color: "5B21B6" }));
      children.push(L.spacer(80));
    }
  }
}
const guide = cat.config_guide || {};
if ((guide.firewall || []).length) {
  children.push(L.H1(`${n++}. ${T.fwc}`));
  children.push(L.P(T.fwc_intro));
  guide.firewall.forEach((x) => children.push(L.bullet(tr(x))));
  if (isCP && (guide.checkpoint || []).length) { children.push(L.H2(T.fwc_cp)); guide.checkpoint.forEach((x) => children.push(L.bullet(tr(x)))); }
}

children.push(L.H1(`${n}. ${T.annex}`));
children.push(L.table([{ h: T.field, w: 1.4 }, { h: T.value, w: 5 }], [
  [T.run, `${run.id} (${run.label})`], [T.start, fmtDate(run.created)],
  ...Object.entries(run.agents).map(([nm, a]) => [`${T.client} ${nm}`, `${(a.env || "").toUpperCase()} · ${a.src || ""} · ${a.results.length} · ${a.started ? fmtDate(a.started) : ""} → ${a.finished ? fmtDate(a.finished) : T.notfinished}`]),
  [T.server, srvIp], [T.envs, (cfg.environments || []).map((e) => `${e.name.toUpperCase()} ${e.ip}`).join(" · ")],
  [T.catalog, T.catline(cat.cases.length, cat.cases.reduce((a, c) => a + c.checks.length, 0))],
]));
children.push(L.spacer());
children.push(L.P(T.logs));

L.write(L.makeDoc({ title: `${T.title} · ${run.id}`, children, footer: T.footer }), outF);
