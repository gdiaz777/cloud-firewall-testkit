# Included by catalog.py (same namespace: T, case, chk, hk, S, EVI_STD…).
# Operator-side cases (control agent), performance cases (one client) and manual procedures.

EVI_CTRL = T("Resultado del portal con los tiempos medidos, salida del agente de control y consola de la nube y de la gestión.",
             "Portal result with the measured times, control agent output and the cloud and management consoles.")
EVI_PERF = T("Resultado del portal (Word/CSV) con las cifras medidas; métricas de CPU de los gateways durante la prueba.",
             "Portal result (Word/CSV) with the measured figures; gateway CPU metrics during the test.")
REQ_CTRL = T("Agente de control en marcha con credenciales de la nube (lectura; las pruebas de HA cambian el grupo de autoescalado y las ACL de red) y de la API de gestión.",
             "Control agent running with cloud credentials (read; HA checks change the Auto Scaling group and network ACLs) and Management API credentials.")
REQ_PERF = T("Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.",
             "Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.")
PERF = dict(roles=["perf_client"], needs=["roles.perf_client"])
X = "{NET:exception_port}"
DIS = dict(disruptive=True)

# ------------------------------------------------------------------ NET
case("NET-06", "critical", T("Caminos alternativos y bypass", "Alternative paths and bypass"),
     T("Ningún camino de red permite que el tráfico de los workloads evite el firewall.", "No network path lets workload traffic avoid the firewall."),
     T("Se auditan las tablas de rutas de las subredes de workload (sin IGW, NAT, peering, VGW ni endpoints de gateway), la tabla del Transit Gateway de los spokes (todo hacia el attachment de inspección con appliance mode) y los peerings.",
       "Audits the route tables of the workload subnets (no IGW, NAT, peering, VGW or gateway endpoints), the Transit Gateway route table of the spokes (everything to the inspection attachment with appliance mode) and peerings."),
     REQ_CTRL, EVI_CTRL, [
         hk(T("Auditoría de rutas de workload y del TGW", "Workload and TGW route audit"), "PASS", "aws.route_audit",
            T("Lee las rutas reales de la cuenta: cualquier ruta que salte la inspección es un fallo.", "Reads the actual routes of the account: any route that skips inspection is a failure."), "Architecture"),
     ])

# ------------------------------------------------------------------ POL
case("POL-14", "medium", T("Reglas sin uso", "Unused rules"),
     T("Se identifican las reglas sin tráfico para revisarlas o eliminarlas.", "Rules without traffic are identified for review or removal."),
     T("Contadores de aciertos (hit count) de cada regla de las capas de acceso del paquete de política, por API de gestión.", "Hit counters of every rule of the access layers of the policy package, through the Management API."),
     T("Contadores de aciertos activos en los gateways.", "Hit counters enabled on the gateways."), EVI_CTRL, [
         hk(T("Reglas sin aciertos y deshabilitadas", "Rules without hits and disabled rules"), "MEASURE", "fw.unused_rules",
            T("Lista de candidatas a limpieza.", "List of cleanup candidates."), "Management"),
     ])
case("POL-16", "high", T("Política declarativa y control de deriva", "Declarative policy and drift control"),
     T("Los cambios hechos fuera del flujo declarativo se detectan.", "Changes made outside the declarative flow are detected."),
     T("Se compara la política publicada con una línea base (instantánea normalizada de las capas de acceso, amenazas e inspección HTTPS). Para demostrar la detección se añade por API una regla deshabilitada, se publica, se comprueba que aparece como deriva y se elimina.",
       "The published policy is compared with a baseline (normalized snapshot of the access, threat and HTTPS inspection layers). To prove detection, a disabled rule is added through the API and published, it must show up as drift, and it is removed."),
     T("La política se construye por código (scripts del kit o Terraform). Línea base guardada por el agente de control.", "The policy is built as code (kit scripts or Terraform). Baseline stored by the control agent."), EVI_CTRL, [
         hk(T("Detección de un cambio fuera de banda", "Detection of an out-of-band change"), "PASS", "fw.policy_drift",
            T("Se publica un cambio temporal (regla deshabilitada) y se retira.", "A temporary change (disabled rule) is published and removed."), "Management"),
     ])

# ------------------------------------------------------------------ IPS / THR
case("IPS-03", "high", T("Configuración y actualización de firmas IPS", "IPS signature configuration and updates"),
     T("Las firmas están al día y los perfiles activan las protecciones según criterios explícitos.", "Signatures are up to date and profiles activate protections on explicit criteria."),
     T("Estado del paquete IPS (versión instalada, última disponible, fecha) y criterios de activación de los perfiles de prevención (impacto, severidad, confianza).",
       "IPS package status (installed and latest version, date) and activation criteria of the prevention profiles (impact, severity, confidence)."),
     T("Actualización automática de IPS en la gestión.", "Automatic IPS updates on the management."), EVI_CTRL, [
         hk(T("Versión de firmas y perfiles", "Signature version and profiles"), "PASS", "fw.ips_status",
            T("Firmas de menos de 7 días o sin actualización pendiente.", "Signatures newer than 7 days or no pending update."), "IPS"),
     ])
case("IPS-10", "high", T("Tiempo de reacción a amenazas y propagación", "Threat reaction time and propagation"),
     T("Un indicador de compromiso nuevo se aplica en los gateways en un tiempo medido.", "A new indicator of compromise is enforced on the gateways within a measured time."),
     T("Se crea por API un indicador (dominio, Prevent), se publica e instala la política de amenazas y un cliente intenta conectar a ese dominio hasta que se bloquea; luego se elimina.",
       "An indicator (domain, Prevent) is created through the API, the threat policy is published and installed, and a client connects to that domain until it is blocked; then it is removed."),
     T("Anti-bot activo en la salida a Internet. Dominio de prueba en internet.ioc_test_domain (se fuerza su resolución a la IP del sitio permitido).",
       "Anti-bot enabled on Internet egress. Test domain in internet.ioc_test_domain (resolved to the IP of the allowed site)."), EVI_CTRL, [
         hk(T("De indicador nuevo a bloqueo efectivo", "From new indicator to effective block"), "PASS", "fw.ioc_reaction",
            T("Instala la política de amenazas dos veces en los gateways de prueba.", "Installs the threat policy twice on the test gateways."), "Anti-bot (C&C)", **DIS),
     ])
case("THR-06", "high", T("Actualización e inteligencia de amenazas", "Threat intelligence updates"),
     T("Las bases de anti-malware, anti-bot, URL y aplicaciones están actualizadas en cada gateway.", "Anti-malware, anti-bot, URL and application databases are up to date on every gateway."),
     T("Estado de actualización de cada base en los gateways (run-script) y de los objetos actualizables (GEO, servicios en línea).",
       "Update status of every database on the gateways (run-script) and of the updatable objects (GEO, online services)."),
     T("Acceso de los gateways a los servicios de actualización del fabricante.", "Gateway access to the vendor update services."), EVI_CTRL, [
         hk(T("Estado de actualización por gateway", "Update status per gateway"), "PASS", "fw.tp_updates",
            T("Cualquier base con error o sin actualizar es un fallo.", "Any database with errors or not updated is a failure."), "Anti-malware / Anti-bot (C&C)"),
     ])

# ------------------------------------------------------------------ OBS
case("OBS-01", "critical", T("Registros allow/deny por conexión", "Allow/deny logs per connection"),
     T("Cada conexión permitida o denegada deja un registro completo y consultable.", "Every allowed or denied connection leaves a complete, searchable log."),
     T("Un cliente abre una conexión permitida (tcp/80) y otra denegada (tcp/22) al servidor y el agente de control las busca en los registros por API, midiendo cuánto tardan en aparecer y qué campos traen.",
       "A client opens an allowed (tcp/80) and a denied (tcp/22) connection to the server and the control agent finds them in the logs through the API, measuring how long they take to show up and which fields they carry."),
     T("Registro activado en las reglas de segmentación y en la de limpieza.", "Logging enabled on the segmentation and cleanup rules."), EVI_CTRL, [
         hk(T("Registro de conexión permitida y denegada", "Log of an allowed and a denied connection"), "PASS", "fw.logs_connection",
            T("Campos: hora, acción, regla, capa, origen, destino, servicio y gateway.", "Fields: time, action, rule, layer, source, destination, service and gateway."), "Logging"),
     ])
case("OBS-02", "critical", T("Trazabilidad de protecciones NGFW", "Traceability of NGFW protections"),
     T("Los eventos de IPS, anti-malware y filtrado URL identifican la protección, severidad, confianza y regla.", "IPS, anti-malware and URL filtering events identify the protection, severity, confidence and rule."),
     T("Un cliente genera un ataque SQLi, una descarga EICAR y un acceso a un FQDN bloqueado; el agente de control busca los eventos y comprueba sus campos.",
       "A client generates an SQLi attack, an EICAR download and an access to a blocked FQDN; the control agent finds the events and checks their fields."),
     T("IPS, anti-malware y filtrado URL en Prevent con registro.", "IPS, anti-malware and URL filtering in Prevent with logging."), EVI_CTRL, [
         hk(T("Eventos de IPS, anti-malware y URL", "IPS, anti-malware and URL events"), "PASS", "fw.logs_threat",
            T("El evento debe nombrar la protección y su severidad.", "The event must name the protection and its severity."), "Logging"),
     ])
case("OBS-08", "high", T("Monitorización de salud, recursos y alertas", "Health, resources and alert monitoring"),
     T("Se conoce el estado de cada gateway y hay alertas configuradas.", "The state of every gateway is known and alerts are configured."),
     T("Nube: estado del grupo de autoescalado y de los destinos del balanceador, métricas de CPU y alarmas. Gateways: CPU, memoria, conexiones, disco y procesos.",
       "Cloud: state of the Auto Scaling group and load balancer targets, CPU metrics and alarms. Gateways: CPU, memory, connections, disk and processes."),
     REQ_CTRL, EVI_CTRL, [
         hk(T("Salud en la nube y alarmas", "Cloud health and alarms"), "PASS", "aws.health", T("Destinos sanos, métricas y al menos una alarma.", "Healthy targets, metrics and at least one alarm."), "Monitoring"),
         hk(T("Salud de los gateways", "Gateway health"), "PASS", "fw.health", T("Ningún proceso caído.", "No process down."), "Monitoring"),
     ])

# ------------------------------------------------------------------ HA
HA_REQ = T("Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).",
           "Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).")
HA_HOW = T("Mientras dura el evento, cada cliente sondea cada segundo el servidor (este-oeste), Internet y un flujo denegado; se mide la interrupción más larga y se comprueba que el flujo denegado nunca pasa. Los fallos se simulan de forma reversible: ACL de red con denegación de la IP del gateway (/32) y procesos de salud del grupo suspendidos durante la prueba.",
           "While the event lasts, every client probes the server (east-west), the Internet and a denied flow once per second; the longest interruption is measured and the denied flow must never pass. Failures are simulated reversibly: network ACL deny of the gateway IP (/32) and health processes of the group suspended during the test.")
case("HA-01", "critical", T("Caída de instancia de inspección", "Inspection instance failure"),
     T("La pérdida de un gateway se detecta, el servicio continúa y el grupo lo reemplaza con la política aplicada.", "The loss of a gateway is detected, the service continues and the group replaces it with the policy applied."),
     T("Se termina un gateway en el grupo de autoescalado. Se miden: detección en el GWLB, lanzamiento y alta del sustituto, registro en la gestión con política (CME) y retirada del objeto antiguo. " + HA_HOW["es"],
       "A gateway is terminated in the Auto Scaling group. Measured: detection by the GWLB, launch and registration of the replacement, registration in the management with policy (CME) and removal of the old object. " + HA_HOW["en"]),
     HA_REQ, EVI_CTRL, [
         hk(T("Terminar un gateway y medir la recuperación", "Terminate a gateway and measure the recovery"), "PASS", "aws.instance_failure",
            T("Criterio: sustituto en servicio con política e interrupción ≤ ha.max_outage_s.", "Criterion: replacement in service with policy and interruption ≤ ha.max_outage_s."), "Availability", **DIS),
     ])
case("HA-02", "critical", T("Fallo de una zona de disponibilidad", "Availability Zone failure"),
     T("Si caen los gateways de una AZ, los de la otra mantienen el servicio.", "If the gateways of one AZ fail, those of the other AZ keep the service."),
     T("Se aíslan todos los gateways de una AZ durante ha.isolation_s y se restauran. Se informa del balanceo entre zonas y del comportamiento ante destinos no sanos del GWLB. " + HA_HOW["es"],
       "All the gateways of one AZ are isolated for ha.isolation_s and restored. Cross-zone load balancing and GWLB unhealthy-target behaviour are reported. " + HA_HOW["en"]),
     HA_REQ, EVI_CTRL, [
         hk(T("Aislar los gateways de una AZ", "Isolate the gateways of one AZ"), "PASS", "aws.az_failure",
            T("Criterio: interrupción ≤ ha.max_outage_s y recuperación al restaurar.", "Criterion: interruption ≤ ha.max_outage_s and recovery after restoring."), "Availability", **DIS),
     ])
case("HA-03", "critical", T("Comportamiento fail-closed ante fallo de inspección", "Fail-closed behaviour on inspection failure"),
     T("Si no hay inspección disponible, el tráfico se corta: nunca pasa sin inspeccionar.", "If no inspection is available, traffic stops: it never passes uninspected."),
     T("Se aíslan todos los gateways a la vez (plano de datos de inspección caído) y se cuenta cualquier flujo que llegue a pasar mientras tanto; después se restaura y se mide la recuperación. " + HA_HOW["es"],
       "All the gateways are isolated at once (inspection data plane down) and any flow that still passes is counted; then they are restored and the recovery is measured. " + HA_HOW["en"]),
     HA_REQ, EVI_CTRL, [
         hk(T("Aislar todo el plano de inspección", "Isolate the whole inspection tier"), "PASS", "aws.fail_closed",
            T("Criterio: cero flujos sin inspección y recuperación al restaurar.", "Criterion: zero uninspected flows and recovery after restoring."), "Availability", **DIS),
     ])
case("HA-04", "critical", T("Failover y persistencia de sesiones stateful", "Failover and stateful session persistence"),
     T("Se documenta qué sesiones establecidas sobreviven a la pérdida de un gateway.", "Documents which established sessions survive the loss of a gateway."),
     T("Cada cliente mantiene 20 sesiones HTTP keep-alive (una petición cada 2 s) durante la pérdida de gateways de HA-01/HA-02 (o un aislamiento propio si se ejecuta sola) y se cuenta cuántas sobreviven.",
       "Every client keeps 20 HTTP keep-alive sessions (one request every 2 s) during the gateway loss of HA-01/HA-02 (or its own isolation when run alone) and the surviving ones are counted."),
     HA_REQ, EVI_CTRL, [
         hk(T("Sesiones largas durante la pérdida de un gateway", "Long sessions during a gateway loss"), "MEASURE", "aws.session_failover",
            T("Medida: sesiones supervivientes y cortadas.", "Measure: surviving and cut sessions."), "Availability", **DIS),
     ])
case("HA-05", "high", T("Escalado horizontal hacia arriba y retorno", "Horizontal scale-out and back"),
     T("Un gateway nuevo entra en servicio con política sin cortar el tráfico y se retira limpiamente.", "A new gateway goes into service with policy without cutting traffic and is removed cleanly."),
     T("Se sube en uno la capacidad deseada del grupo (protegiendo los gateways existentes), se mide el alta (instancia, destino sano, registro con política) y se vuelve a la capacidad inicial midiendo la baja (desregistro, terminación, objeto retirado). " + HA_HOW["es"],
       "The desired capacity of the group is raised by one (protecting the existing gateways), the scale-out is measured (instance, healthy target, registration with policy) and the group goes back to the initial capacity measuring the scale-in (deregistration, termination, object removed). " + HA_HOW["en"]),
     HA_REQ, EVI_CTRL, [
         hk(T("Escalar +1 y volver", "Scale +1 and back"), "PASS", "aws.scale_out",
            T("Incluye las políticas de escalado configuradas.", "Includes the configured scaling policies."), "Availability", **DIS),
     ])

# ------------------------------------------------------------------ PERF
case("PERF-01", "critical", T("Throughput con política L3/L4", "Throughput with L3/L4 policy"),
     T("Se mide el caudal a través del firewall solo con control de acceso.", "Measures throughput through the firewall with access control only."),
     T("iperf3 al puerto de excepción (permitido entre entornos y excluido de la prevención de amenazas): subida y bajada con 4 flujos y un flujo único (límite por flujo).",
       "iperf3 to the exception port (allowed between environments and excluded from threat prevention): upload and download with 4 streams and a single stream (per-flow limit)."),
     REQ_PERF, EVI_PERF, [
         chk("iperf", T("Subida TCP, 4 flujos, 20 s", "TCP upload, 4 streams, 20 s"), "MEASURE", T("Caudal agregado del cliente al servidor.", "Aggregate throughput client → server."), "Performance", port=X, streams=4, seconds=20, **PERF),
         chk("iperf", T("Bajada TCP, 4 flujos, 20 s", "TCP download, 4 streams, 20 s"), "MEASURE", T("Servidor → cliente (-R).", "Server → client (-R)."), "Performance", port=X, streams=4, seconds=20, args=["-R"], **PERF),
         chk("iperf", T("Flujo TCP único, 20 s", "Single TCP stream, 20 s"), "MEASURE", T("Un flujo va siempre al mismo gateway y núcleo: límite por flujo.", "One flow always lands on the same gateway and core: per-flow limit."), "Performance", port=X, streams=1, seconds=20, **PERF),
     ])
case("PERF-02", "critical", T("Throughput con IPS y protección avanzada", "Throughput with IPS and advanced protection"),
     T("Se mide el caudal con todas las capacidades de inspección activas.", "Measures throughput with every inspection capability enabled."),
     T("Descargas paralelas de un fichero de 200 MB por HTTP (IPS, anti-malware, DLP) y por HTTPS descifrado y sin descifrar, desde el servidor de pruebas.",
       "Parallel downloads of a 200 MB file over HTTP (IPS, anti-malware, DLP) and over decrypted and not decrypted HTTPS, from the test server."),
     REQ_PERF, EVI_PERF, [
         chk("dl_bench", T("HTTP inspeccionado, 4 descargas en paralelo", "Inspected HTTP, 4 parallel downloads"), "MEASURE", T("Perfil completo de amenazas.", "Full threat profile."), "Performance / IPS / Anti-malware", url=f"http://{S}/perf/200m.bin", parallel=4, seconds=30, **PERF),
         chk("dl_bench", T("HTTPS descifrado, 4 descargas en paralelo", "Decrypted HTTPS, 4 parallel downloads"), "MEASURE", T("Inspección TLS más perfil completo.", "TLS inspection plus full profile."), "Performance / TLS inspection", url=f"https://{INS}/perf/200m.bin", args=R_INS, parallel=4, seconds=30, **PERF),
         chk("dl_bench", T("HTTPS sin descifrar, 4 descargas en paralelo", "Not decrypted HTTPS, 4 parallel downloads"), "MEASURE", T("Referencia sin descifrado.", "Reference without decryption."), "Performance / TLS inspection (bypass)", url=f"https://{NOD}/perf/200m.bin", args=R_NOD, parallel=4, seconds=30, **PERF),
     ])
case("PERF-03", "critical", T("Latencia y jitter p50/p95/p99", "Latency and jitter p50/p95/p99"),
     T("Se mide la latencia que añade el camino de inspección.", "Measures the latency added by the inspection path."),
     T("200 muestras de eco ICMP, de establecimiento TCP y de petición HTTP completa al servidor de pruebas.", "200 samples of ICMP echo, TCP handshake and full HTTP request to the test server."),
     REQ_PERF, EVI_PERF, [
         chk("latency", T("ICMP (200 ecos)", "ICMP (200 echoes)"), "MEASURE", T("Ida y vuelta de red.", "Network round trip."), "Performance", mode="icmp", n=200, **PERF),
         chk("latency", T("Establecimiento TCP (200)", "TCP handshake (200)"), "MEASURE", T("Incluye la decisión del firewall para cada conexión nueva.", "Includes the firewall decision for every new connection."), "Performance", mode="tcp", n=200, port=80, **PERF),
         chk("latency", T("Petición HTTP completa (200)", "Full HTTP request (200)"), "MEASURE", T("Incluye la inspección del contenido.", "Includes content inspection."), "Performance", mode="http", n=200, **PERF),
     ])
case("PERF-04", "high", T("Conexiones simultáneas", "Concurrent connections"),
     T("El firewall mantiene muchas sesiones abiertas a la vez.", "The firewall keeps many sessions open at the same time."),
     T("2000 sesiones TCP abiertas a la vez desde un cliente, cada una usada, mantenida 30 s y usada otra vez.", "2000 TCP sessions open at the same time from one client, each one used, held for 30 s and used again."),
     REQ_PERF, EVI_PERF, [
         chk("concurrent", T("2000 sesiones simultáneas", "2000 concurrent sessions"), "MEASURE", T("Capacidad de la tabla de estado (limitada por un único cliente).", "State table capacity (limited by a single client)."), "Performance", n=2000, hold=30, **PERF),
     ])
case("PERF-05", "high", T("Conexiones nuevas por segundo (CPS)", "New connections per second (CPS)"),
     T("Se mide la tasa de conexiones nuevas que procesa el firewall.", "Measures the rate of new connections processed by the firewall."),
     T("Peticiones HTTP cortas (conectar, GET, cerrar) con 64 en paralelo durante 20 s.", "Short HTTP requests (connect, GET, close) with 64 in parallel for 20 s."),
     REQ_PERF, EVI_PERF, [
         chk("cps", T("CPS sostenido 20 s", "Sustained CPS 20 s"), "MEASURE", T("Medido desde un cliente: es un mínimo, no el máximo del firewall.", "Measured from one client: a lower bound, not the firewall maximum."), "Performance", seconds=20, concurrency=64, **PERF),
     ])
case("PERF-06", "high", T("Ráfagas y carga sostenida", "Bursts and sustained load"),
     T("El caudal se mantiene estable con carga continua y absorbe ráfagas.", "Throughput stays stable under continuous load and absorbs bursts."),
     T("iperf3 sostenido 120 s (mínimo, media y máximo por segundo, retransmisiones), ráfaga de 16 flujos y ráfaga de conexiones nuevas.",
       "iperf3 sustained for 120 s (min, average and max per second, retransmissions), a burst of 16 streams and a burst of new connections."),
     REQ_PERF, EVI_PERF, [
         chk("iperf", T("Carga sostenida 120 s", "Sustained load 120 s"), "MEASURE", T("Estabilidad segundo a segundo.", "Second-by-second stability."), "Performance", port=X, streams=4, seconds=120, **PERF),
         chk("iperf", T("Ráfaga de 16 flujos, 15 s", "Burst of 16 streams, 15 s"), "MEASURE", T("Reparto entre gateways y núcleos.", "Spread across gateways and cores."), "Performance", port=X, streams=16, seconds=15, **PERF),
         chk("cps", T("Ráfaga de conexiones (256 en paralelo, 10 s)", "Connection burst (256 in parallel, 10 s)"), "MEASURE", T("Pico de conexiones nuevas.", "Peak of new connections."), "Performance", seconds=10, concurrency=256, **PERF),
     ])
case("PERF-07", "high", T("Tamaño de paquete y TCP/UDP", "Packet size and TCP/UDP"),
     T("Se documenta el rendimiento con paquetes pequeños y grandes en TCP y UDP.", "Documents performance with small and large packets over TCP and UDP."),
     T("iperf3 UDP a 300 Mbit/s con datagramas de 64, 512 y 1400 bytes (paquetes por segundo, pérdida, jitter) y TCP con MSS de 536 bytes.",
       "iperf3 UDP at 300 Mbit/s with 64, 512 and 1400-byte datagrams (packets per second, loss, jitter) and TCP with a 536-byte MSS."),
     REQ_PERF, EVI_PERF, [
         chk("iperf", T("UDP 64 bytes", "UDP 64 bytes"), "MEASURE", T("Paquetes pequeños: límite en paquetes por segundo.", "Small packets: packets-per-second limit."), "Performance", port=X, seconds=10, args=["-u", "-b", "300M", "-l", "64"], label="64 B, ", **PERF),
         chk("iperf", T("UDP 512 bytes", "UDP 512 bytes"), "MEASURE", T("Tamaño medio.", "Medium size."), "Performance", port=X, seconds=10, args=["-u", "-b", "300M", "-l", "512"], label="512 B, ", **PERF),
         chk("iperf", T("UDP 1400 bytes", "UDP 1400 bytes"), "MEASURE", T("Cerca de la MTU (con GENEVE).", "Close to the MTU (with GENEVE)."), "Performance", port=X, seconds=10, args=["-u", "-b", "300M", "-l", "1400"], label="1400 B, ", **PERF),
         chk("iperf", T("TCP con MSS 536", "TCP with MSS 536"), "MEASURE", T("Segmentos TCP pequeños.", "Small TCP segments."), "Performance", port=X, streams=4, seconds=15, args=["-M", "536"], **PERF),
     ])
case("PERF-08", "high", T("Consumo de recursos y coste por carga", "Resource usage and cost per load"),
     T("Se relaciona la carga con el consumo de los gateways y su coste.", "Relates load with gateway resource usage and cost."),
     T("El agente de control lanza carga desde el cliente de rendimiento (iperf3 y descargas HTTP inspeccionadas) mientras muestrea la CPU de los gateways cada 5 s y en CloudWatch, y calcula el coste de cómputo por hora con la API de precios.",
       "The control agent runs load from the performance client (iperf3 and inspected HTTP downloads) while sampling the gateways' CPU every 5 s and in CloudWatch, and computes the compute cost per hour with the Pricing API."),
     REQ_CTRL, EVI_CTRL, [
         hk(T("CPU y coste bajo carga", "CPU and cost under load"), "MEASURE", "aws.load_resources", T("Medida combinada de carga, CPU y coste.", "Combined load, CPU and cost measure."), "Performance / Cost", **DIS),
     ])

# ------------------------------------------------------------------ OPS
case("OPS-01", "high", T("Onboarding automatizado y mínimo privilegio", "Automated onboarding and least privilege"),
     T("La gestión lee la cuenta con un rol de solo lectura y acotado.", "The management reads the account with a read-only, scoped role."),
     T("Se analiza el rol que usa la gestión (CME) para descubrir el grupo de autoescalado: acciones permitidas, comodines, principal de confianza y ExternalId.",
       "Analyses the role the management (CME) uses to discover the Auto Scaling group: allowed actions, wildcards, trusted principal and ExternalId."),
     T("aws.cme_role_arn configurado en el agente de control.", "aws.cme_role_arn set on the control agent."), EVI_CTRL, [
         hk(T("Permisos del rol de la gestión", "Permissions of the management role"), "PASS", "aws.cme_least_privilege",
            T("Sin comodines ni escrituras, con ExternalId.", "No wildcards or writes, with ExternalId."), "Operations"),
     ])
case("OPS-03", "high", T("Políticas por API, Terraform y CI/CD", "Policies through API, Terraform and CI/CD"),
     T("Un cambio de política hecho por API se aplica de extremo a extremo y se revierte.", "A policy change made through the API is enforced end to end and rolled back."),
     T("Se añade por API una regla temporal que bloquea http de un cliente al servidor, se publica e instala, se mide cuándo se bloquea el tráfico, se elimina, se reinstala y se mide cuándo vuelve.",
       "A temporary rule blocking http from a client to the server is added through the API, published and installed; the time to block is measured; then it is removed, reinstalled and the time to recover is measured."),
     T("Acceso de escritura a la API de gestión (solo objetos TK_ y gateways de prueba).", "Write access to the Management API (TK_ objects and test gateways only)."), EVI_CTRL, [
         hk(T("Cambio y reversión por API medidos", "API change and rollback, measured"), "PASS", "fw.api_pipeline",
            T("Instala la política de acceso dos veces en los gateways de prueba.", "Installs the access policy twice on the test gateways."), "Operations", **DIS),
     ])

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog_manual.py"), encoding="utf-8").read())
