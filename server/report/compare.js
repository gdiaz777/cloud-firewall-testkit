// Comparison report: several runs (e.g. different security solutions) side by side.
//   node compare.js <tests.json> <workdir with PNGs> <out.docx> <en|es> <run1.json> <run2.json> …
const fs = require("fs");
const path = require("path");
const L = require("./lib");
const [catF, work, outF, langArg, ...runFs] = process.argv.slice(2);
const LANG = langArg === "es" ? "es" : "en";
const cat = JSON.parse(fs.readFileSync(catF, "utf8"));
const tr = (x) => (x && typeof x === "object" ? x[LANG] || x.en : x || "");
const RANK = { FAIL: 4, ERROR: 4, OK: 3, INFO: 2, SKIP: 1 };
const runs = runFs.map((f) => JSON.parse(fs.readFileSync(f, "utf8")));
runs.forEach((r) => (r.solution = r.solution || ((r.config || {}).solution || {}).name || r.id));
const perCheck = (r) => {
  const st = {};
  for (const a of Object.values(r.agents)) for (const x of a.results) if ((RANK[x.status] || 0) > (RANK[st[x.id]] || 0)) st[x.id] = x.status;
  return st;
};
const PC = runs.map(perCheck);
const detail = runs.map((r) => {
  const d = {};
  for (const a of Object.values(r.agents)) for (const x of a.results) if (!d[x.id] || x.status === "FAIL") d[x.id] = x;
  return d;
});

const T = {
  en: { kicker: "FIREWALL TESTKIT · SOLUTION COMPARISON", title: "Security solution comparison", sub: "Same tests, same environment, different security solutions",
    footer: "Firewall Testkit · Confidential · Page ", contents: "Contents", solutions: "Solutions compared", date: "Date",
    s1: "Summary", lead: (n) => `The same catalog of automated checks was run against ${n} solutions. A check counts as expected when every client obtained the expected result.`,
    sol: "Solution", exp: "Expected results", cases: "Cases passing", tls: "Checks over TLS", bad: "Unexpected", runid: "Run",
    f1: "Figure 1. Expected results by domain and solution.", s2: "Results by case", case: "Case", test: "Test",
    s3: "Checks with different results", s3lead: "Checks where at least one solution did not obtain the expected result while another did.", none: "Every solution obtained the same results.",
    check: "Check", expected: "Expected", s4: "Method", method: "Each run was executed with the same Firewall Testkit catalog and clients; only the security solution and its configuration changed. Results come from the clients (connection reset or drop, block page, certificate issuer), not from vendor logs, so the comparison is independent of the vendor. Measurements (MTU, TLS overhead) and informative checks are not counted.",
    V: { Cumple: "Pass", Parcial: "Partial", "No cumple": "Fail", Medida: "Measure", "-": "—" }, ST: { OK: "Pass", FAIL: "Fail", ERROR: "Fail", INFO: "Measure", SKIP: "N/A" },
    EXP: { ALLOW: "Allowed", BLOCK: "Blocked", INSPECTED: "Decrypted", NOT_INSPECTED: "Not decrypted", VALID: "Cert. valid", INVALID: "Cert. rejected", PRESERVED: "IP preserved", LIMITED: "Authorized only", MEASURE: "Measure", NO_FLOW: "No flow" } },
  es: { kicker: "FIREWALL TESTKIT · COMPARATIVA DE SOLUCIONES", title: "Comparativa de soluciones de seguridad", sub: "Mismas pruebas, mismo entorno, distintas soluciones de seguridad",
    footer: "Firewall Testkit · Confidencial · Página ", contents: "Contenido", solutions: "Soluciones comparadas", date: "Fecha",
    s1: "Resumen", lead: (n) => `Se ejecutó el mismo catálogo de comprobaciones automáticas contra ${n} soluciones. Una comprobación cuenta como esperada cuando todos los clientes obtuvieron el resultado esperado.`,
    sol: "Solución", exp: "Resultado esperado", cases: "Casos que cumplen", tls: "Pruebas sobre TLS", bad: "No esperados", runid: "Ejecución",
    f1: "Figura 1. Resultado esperado por dominio y solución.", s2: "Resultado por caso", case: "Caso", test: "Prueba",
    s3: "Comprobaciones con resultado distinto", s3lead: "Comprobaciones en las que al menos una solución no obtuvo el resultado esperado y otra sí.", none: "Todas las soluciones obtuvieron los mismos resultados.",
    check: "Comprobación", expected: "Esperado", s4: "Método", method: "Cada ejecución usó el mismo catálogo y los mismos clientes de Firewall Testkit; solo cambiaron la solución de seguridad y su configuración. Los resultados salen de los clientes (conexión reiniciada o descartada, página de bloqueo, emisor del certificado) y no de los registros del fabricante, por lo que la comparación es independiente del fabricante. Las medidas (MTU, sobrecoste TLS) y las pruebas informativas no puntúan.",
    V: { Cumple: "Cumple", Parcial: "Parcial", "No cumple": "No cumple", Medida: "Medida", "-": "—" }, ST: { OK: "Cumple", FAIL: "No cumple", ERROR: "No cumple", INFO: "Medida", SKIP: "No aplica" },
    EXP: { ALLOW: "Permitido", BLOCK: "Bloqueado", INSPECTED: "Descifrado", NOT_INSPECTED: "Sin descifrar", VALID: "Cert. válido", INVALID: "Cert. rechazado", PRESERVED: "IP conservada", LIMITED: "Solo autorizados", MEASURE: "Medida", NO_FLOW: "Sin flujo" } },
}[LANG];

const informative = new Set(cat.cases.flatMap((c) => c.checks.filter((k) => k.informative).map((k) => k.id)));
const caseVerdict = (pc, cid) => {
  const st = Object.entries(pc).filter(([id, v]) => id.startsWith(cid + ".") && v !== "SKIP" && v !== "INFO" && !informative.has(id)).map(([, v]) => v);
  if (!st.length) return Object.keys(pc).some((id) => id.startsWith(cid + ".")) ? "Medida" : "-";
  const f = st.filter((v) => v !== "OK").length;
  return f === 0 ? "Cumple" : f === st.length ? "No cumple" : "Parcial";
};
const tlsIds = new Set(cat.cases.flatMap((c) => c.checks.filter((k) => (k.blade || "").includes("TLS inspection")).map((k) => k.id)));
const summary = runs.map((r, i) => {
  const ev = Object.entries(PC[i]).filter(([id, v]) => (v === "OK" || v === "FAIL" || v === "ERROR") && !informative.has(id));
  const ok = ev.filter(([, v]) => v === "OK").length;
  const tls = ev.filter(([id]) => tlsIds.has(id.split(".").slice(0, 2).join(".")));
  const verdicts = cat.cases.map((c) => caseVerdict(PC[i], c.id)).filter((v) => v !== "-" && v !== "Medida");
  return { ok, n: ev.length, pct: ev.length ? Math.round((100 * ok) / ev.length) : 0, cases: `${verdicts.filter((v) => v === "Cumple").length}/${verdicts.length}`,
    tls: `${tls.filter(([, v]) => v === "OK").length}/${tls.length}`, bad: ev.length - ok };
});
const fmt = (iso) => new Date(iso).toLocaleDateString(LANG === "es" ? "es-ES" : "en-GB", { dateStyle: "long" });

const children = [
  ...L.cover({ kicker: T.kicker, title: T.title, subtitle: T.sub, meta: [[T.solutions, runs.map((r) => r.solution).join(" · ")], [T.date, fmt(new Date().toISOString())]] }),
  ...L.toc(T.contents),
  L.H1(`1. ${T.s1}`),
  L.P(T.lead(runs.length)),
  L.table([{ h: T.sol, w: 2 }, { h: T.exp, w: 1.3, align: "center" }, { h: T.cases, w: 1.1, align: "center" }, { h: T.tls, w: 1.1, align: "center" }, { h: T.bad, w: 1.2, align: "center" }, { h: T.runid, w: 1.4 }],
    runs.map((r, i) => [r.solution, `${summary[i].ok}/${summary[i].n} (${summary[i].pct} %)`, summary[i].cases, summary[i].tls, String(summary[i].bad), r.id])),
  L.spacer(160),
  ...(fs.existsSync(path.join(work, "compare_domains.png")) ? [L.image(path.join(work, "compare_domains.png"), 620), L.caption(T.f1)] : []),
  L.H1(`2. ${T.s2}`),
];
for (const d of cat.domains) {
  const cs = cat.cases.filter((c) => c.domain === d.id && runs.some((_, i) => caseVerdict(PC[i], c.id) !== "-"));
  if (!cs.length) continue;
  children.push(L.H2(`${d.id} · ${tr(d.name)}`));
  children.push(L.table([{ h: T.case, w: 0.8 }, { h: T.test, w: 2.6 }, ...runs.map((r) => ({ h: r.solution, w: 1.2, status: true }))],
    cs.map((c) => [c.id, tr(c.title), ...runs.map((_, i) => T.V[caseVerdict(PC[i], c.id)])])));
}
const allIds = [...new Set(PC.flatMap((p) => Object.keys(p)))].filter((id) => !informative.has(id)).sort();
const diff = allIds.filter((id) => { const v = PC.map((p) => p[id]); return v.some((x) => x === "OK") && v.some((x) => x === "FAIL" || x === "ERROR"); });
const nameOf = {}; cat.cases.forEach((c) => c.checks.forEach((k) => (nameOf[k.id] = tr(k.name))));
children.push(L.H1(`3. ${T.s3}`), L.P(T.s3lead));
if (!diff.length) children.push(L.P(T.none));
else children.push(L.table([{ h: T.check, w: 0.9 }, { h: T.test, w: 2.3 }, { h: T.expected, w: 1 }, ...runs.map((r) => ({ h: r.solution, w: 1.2, status: true }))],
  diff.map((id) => { const any = detail.find((d) => d[id]); const x = any && any[id];
    return [id, nameOf[id] || (x && x.name) || id, T.EXP[x && x.expect] || (x && x.expect) || "", ...runs.map((_, i) => T.ST[PC[i][id]] || "—")]; })));
children.push(L.H1(`4. ${T.s4}`), L.P(T.method));

L.write(L.makeDoc({ title: T.title, children, footer: T.footer }), outF);
