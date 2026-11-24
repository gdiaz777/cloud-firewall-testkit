# Included by catalog_ops.py. Manual cases: guided procedure (steps), expected result and evidence. No automated checks.


def manual(id_, prio, title, objective, requires, steps, expected, evidence, how, scope=None):
    case(id_, prio, title, objective, how, requires, evidence, [], mode="manual",
         procedure=[T(a, b) for a, b in steps], expected=expected, **({"scope": scope} if scope else {}))


OUT_LAB = lambda es, en: T("Fuera del laboratorio de referencia: " + es, "Outside the reference lab: " + en)
EV_CONS = T("Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.",
            "Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.")

# ------------------------------------------------------------------ NET
manual("NET-02", "critical", T("Aislamiento y control intra-VPC", "Intra-VPC isolation and control"),
       T("Se identifica qué tráfico dentro de una misma VPC pasa por el firewall y cuál queda fuera.", "Identifies which traffic inside one VPC goes through the firewall and which stays outside."),
       T("Dos instancias en subredes distintas de la misma VPC.", "Two instances in different subnets of the same VPC."),
       [("Despliega dos instancias en subredes distintas de la misma VPC.", "Deploy two instances in different subnets of the same VPC."),
        ("Genera tráfico entre ellas (ICMP, tcp/22, tcp/443) y busca esas conexiones en los registros del firewall.", "Generate traffic between them (ICMP, tcp/22, tcp/443) and look for those connections in the firewall logs."),
        ("Si no aparecen, el tráfico se resuelve por la ruta local de la VPC: documenta el control con security groups/NACL.", "If they do not show up, traffic uses the VPC local route: document the control with security groups/NACLs."),
        ("Si se necesita inspección intra-VPC, añade rutas más específicas (VPC route ingress / subred a subred) hacia el endpoint del firewall y repite.", "If intra-VPC inspection is needed, add more specific routes (subnet to subnet) to the firewall endpoint and repeat.")],
       T("Inventario explícito de flujos intra-VPC inspeccionados y no inspeccionados; ninguna cobertura supuesta.", "Explicit inventory of inspected and uninspected intra-VPC flows; no assumed coverage."), EV_CONS,
       T("Con GWLB se pueden insertar endpoints entre subredes de la misma VPC mediante rutas más específicas que la local (AWS lo permite desde 2021).", "With GWLB, endpoints can be inserted between subnets of the same VPC with routes more specific than the local one."))
manual("NET-04", "high", T("Ingress norte-sur hacia servicios publicados", "North-south ingress to published services"),
       T("El tráfico entrante desde Internet a servicios publicados se inspecciona.", "Inbound traffic from the Internet to published services is inspected."),
       OUT_LAB("necesita un servicio publicado (ALB/NLB) con la ruta de entrada por el firewall.", "needs a published service (ALB/NLB) with the ingress route through the firewall."),
       [("Publica un servicio de prueba detrás de un balanceador en una VPC de ingress.", "Publish a test service behind a load balancer in an ingress VPC."),
        ("Enruta la entrada (IGW edge association o VPC de ingress) a través de los endpoints del firewall.", "Route ingress (IGW edge association or ingress VPC) through the firewall endpoints."),
        ("Desde Internet lanza peticiones legítimas y ataques (SQLi, XSS, escaneo) y verifica bloqueo y registros con la IP real del cliente.", "From the Internet send legitimate requests and attacks (SQLi, XSS, scan) and check blocking and logs with the real client IP.")],
       T("Ataques bloqueados, tráfico legítimo permitido y registros con la IP de origen real.", "Attacks blocked, legitimate traffic allowed and logs with the real source IP."), EV_CONS,
       T("Check Point recomienda ingress con GWLB (preserva la IP de origen) y, para aplicaciones web y API, CloudGuard WAF delante del servicio.", "Check Point recommends GWLB ingress (preserves the source IP) and CloudGuard WAF in front of web apps and APIs."),
       scope="out_of_lab")
manual("NET-08", "high", T("Ruteo selectivo / service chaining", "Selective routing / service chaining"),
       T("Solo el tráfico elegido se envía a inspección y el resto sigue su camino sin romperse.", "Only the selected traffic is sent to inspection and the rest keeps working."),
       T("Tablas de rutas del Transit Gateway editables.", "Editable Transit Gateway route tables."),
       [("Define qué destinos deben pasar por inspección y cuáles no (p. ej. tráfico a un servicio interno de confianza).", "Define which destinations must go through inspection and which not (e.g. traffic to a trusted internal service)."),
        ("Ajusta rutas del TGW/VPC para excluir solo ese destino y comprueba con los registros que el resto sigue inspeccionado.", "Adjust TGW/VPC routes to exclude only that destination and check in the logs that the rest is still inspected."),
        ("Verifica simetría: ambos sentidos del flujo excluido evitan el firewall (si no, se rompe la sesión).", "Check symmetry: both directions of the excluded flow avoid the firewall (otherwise the session breaks).")],
       T("La exclusión afecta solo al destino definido, es simétrica y queda documentada.", "The exclusion affects only the defined destination, is symmetric and is documented."), EV_CONS,
       T("Preferible excluir por política (regla de acceso + excepción de amenazas) antes que por rutas: mantiene registro y visibilidad.", "Prefer excluding by policy (access rule + threat exception) rather than by routes: keeps logging and visibility."))
manual("NET-09", "high", T("Cambio de topología o rutas sin degradar seguridad", "Topology or route change without degrading security"),
       T("Un cambio de rutas o de VPC no abre caminos sin inspección.", "A route or VPC change does not open uninspected paths."),
       T("Entorno de pruebas donde se puedan añadir VPC y rutas.", "Test environment where VPCs and routes can be added."),
       [("Añade un spoke nuevo o cambia una ruta del TGW (como en una operación real).", "Add a new spoke or change a TGW route (as in a real operation)."),
        ("Ejecuta NET-06 (auditoría de rutas) y la matriz de segmentación (NET-01/NET-07) antes y después.", "Run NET-06 (route audit) and the segmentation matrix (NET-01/NET-07) before and after."),
        ("Comprueba que la política agrupa el nuevo spoke por objeto dinámico/etiqueta sin editar reglas.", "Check that the policy picks up the new spoke through a dynamic object/tag without editing rules.")],
       T("Sin rutas de bypass y misma matriz de resultados tras el cambio.", "No bypass routes and the same matrix results after the change."), EV_CONS,
       T("Usar objetos de datacenter (CloudGuard Controller) o etiquetas para que los spokes nuevos hereden la política.", "Use data center objects (CloudGuard Controller) or tags so new spokes inherit the policy."))
manual("NET-10", "high", T("Egress y routing IPv6", "IPv6 egress and routing"),
       T("El tráfico IPv6 se inspecciona igual que el IPv4.", "IPv6 traffic is inspected like IPv4."),
       OUT_LAB("necesita VPC con IPv6 y egress-only IGW enrutado por el firewall.", "needs dual-stack VPCs and an egress-only IGW routed through the firewall."),
       [("Activa IPv6 en un spoke y en la VPC de inspección.", "Enable IPv6 on a spoke and on the inspection VPC."),
        ("Enruta ::/0 hacia el endpoint del firewall y sal a Internet por IPv6.", "Route ::/0 to the firewall endpoint and go out to the Internet over IPv6."),
        ("Repite las pruebas de NET-03 y APP-02 por IPv6 y compara los registros.", "Repeat the NET-03 and APP-02 checks over IPv6 and compare the logs.")],
       T("Mismas decisiones y registros en IPv4 e IPv6.", "Same decisions and logs over IPv4 and IPv6."), EV_CONS,
       T("Confirmar el soporte IPv6 de la versión y del modo GWLB desplegados y crear las reglas con objetos IPv6.", "Confirm IPv6 support of the deployed version and GWLB mode and build the rules with IPv6 objects."), scope="out_of_lab")
manual("NET-11", "medium", T("Conectividad híbrida AWS–on-prem", "Hybrid AWS–on-prem connectivity"),
       T("El tráfico entre la nube y el centro de datos pasa por inspección.", "Traffic between the cloud and the data center goes through inspection."),
       OUT_LAB("necesita VPN o Direct Connect al TGW.", "needs a VPN or Direct Connect to the TGW."),
       [("Conecta una VPN/Direct Connect al TGW y asocia su attachment a la tabla que envía a inspección.", "Connect a VPN/Direct Connect to the TGW and associate its attachment with the table that sends to inspection."),
        ("Genera tráfico on-prem ↔ spokes y comprueba en los registros que se inspecciona en ambos sentidos.", "Generate on-prem ↔ spoke traffic and check in the logs that it is inspected both ways.")],
       T("Tráfico híbrido inspeccionado y simétrico.", "Hybrid traffic inspected and symmetric."), EV_CONS,
       T("Mismo diseño de tablas del TGW que para los spokes; appliance mode en el attachment de inspección.", "Same TGW table design as for spokes; appliance mode on the inspection attachment."), scope="out_of_lab")
manual("NET-12", "medium", T("Conectividad intercloud AWS–Azure", "AWS–Azure intercloud connectivity"),
       T("El tráfico entre nubes se inspecciona con la misma política.", "Traffic between clouds is inspected with the same policy."),
       OUT_LAB("necesita un entorno Azure conectado (VPN/ExpressRoute).", "needs a connected Azure environment (VPN/ExpressRoute)."),
       [("Conecta AWS y Azure (VPN entre TGW y Virtual WAN/VNet).", "Connect AWS and Azure (VPN between the TGW and Virtual WAN/VNet)."),
        ("Despliega un cliente del kit en Azure y ejecuta la matriz de segmentación entre nubes.", "Deploy a kit client in Azure and run the segmentation matrix across clouds."),
        ("Compara la política y los registros en ambas nubes desde la misma consola.", "Compare policy and logs in both clouds from the same console.")],
       T("Misma política y visibilidad unificada en ambas nubes.", "Same policy and unified visibility in both clouds."), EV_CONS,
       T("Una única gestión (Smart-1 Cloud) para gateways de AWS y Azure: mismos objetos, capas y registros.", "A single management (Smart-1 Cloud) for AWS and Azure gateways: same objects, layers and logs."), scope="out_of_lab")

# ------------------------------------------------------------------ POL
manual("POL-03", "critical", T("Granularidad por aplicación, identidad o etiqueta", "Granularity by application, identity or tag"),
       T("Las reglas pueden usar aplicación, identidad y etiquetas de la nube, no solo IP/puerto.", "Rules can use application, identity and cloud tags, not just IP/port."),
       T("Conector de nube (lectura de etiquetas) y, para identidad, un proveedor de identidad.", "Cloud connector (tag reading) and, for identity, an identity provider."),
       [("Crea una regla que use una aplicación (p. ej. bloquear una aplicación concreta) y verifica su efecto con el kit (APP-01).", "Create a rule using an application (e.g. block a given application) and verify it with the kit (APP-01)."),
        ("Crea un objeto dinámico por etiqueta de instancia y úsalo como origen de una regla; cambia la etiqueta de una instancia y comprueba que la regla la sigue.", "Create a dynamic object by instance tag and use it as source of a rule; change an instance tag and check the rule follows it."),
        ("Si aplica, crea una regla por grupo de identidad y verifica el registro con el usuario.", "If applicable, create a rule by identity group and verify the log shows the user.")],
       T("Reglas por aplicación, etiqueta e identidad efectivas y registradas.", "Application, tag and identity rules effective and logged."), EV_CONS,
       T("CloudGuard Controller (objetos de datacenter de AWS por etiqueta) e Identity Awareness; las reglas usan objetos, nunca IP fijas de workloads.", "CloudGuard Controller (AWS data center objects by tag) and Identity Awareness; rules use objects, never fixed workload IPs."))
manual("POL-04", "high", T("Caducidad, aprobación y reversión de excepciones", "Expiry, approval and rollback of exceptions"),
       T("Las excepciones tienen dueño, aprobación y fecha de caducidad, y se pueden revertir.", "Exceptions have an owner, an approval and an expiry date, and can be rolled back."),
       T("Flujo de cambios con aprobación (sesiones con aprobación o ITSM).", "Change workflow with approval (sessions with approval or ITSM)."),
       [("Crea una regla de excepción con fecha de caducidad y comentario con el número de cambio.", "Create an exception rule with an expiry date and a comment with the change number."),
        ("Publica con aprobación de un segundo administrador.", "Publish with approval of a second administrator."),
        ("Verifica que la regla deja de aplicar al caducar y revierte la publicación a la revisión anterior.", "Check the rule stops applying when it expires and revert to the previous revision.")],
       T("Excepción aprobada, caducada automáticamente y revertible con trazabilidad.", "Exception approved, expired automatically and revertible with traceability."), EV_CONS,
       T("Campo «Time» de la regla (objeto de tiempo con fecha de fin), Session approval workflow y revisiones de política (Installation History).", "Rule «Time» field (time object with end date), session approval workflow and policy revisions (Installation History)."))
manual("POL-06", "high", T("Reglas FQDN: rotación de IP, TTL y múltiples A/AAAA", "FQDN rules: IP rotation, TTL and multiple A/AAAA"),
       T("Las reglas por FQDN siguen las IP cambiantes de servicios en la nube.", "FQDN rules follow the changing IPs of cloud services."),
       T("Regla con objeto de dominio (no comodín) y un destino con varias IP y TTL bajo.", "Rule with a domain object (non-wildcard) and a destination with several IPs and low TTL."),
       [("Crea una regla que permita un FQDN con varias A/AAAA y TTL bajo (p. ej. un servicio SaaS).", "Create a rule allowing an FQDN with several A/AAAA records and low TTL (e.g. a SaaS service)."),
        ("Desde un cliente resuelve y conecta repetidamente durante 30 min; anota las IP devueltas.", "From a client resolve and connect repeatedly for 30 min; note the returned IPs."),
        ("Comprueba que todas las conexiones se permiten y que los registros asocian el dominio.", "Check that every connection is allowed and the logs show the domain.")],
       T("Ninguna conexión legítima denegada por cambio de IP.", "No legitimate connection denied because of an IP change."), EV_CONS,
       T("Objetos de dominio FQDN (no «wildcard») resuelven en el gateway; para SaaS conocidos, preferir objetos actualizables (Updatable Objects) del fabricante.", "FQDN domain objects (non-wildcard) resolve on the gateway; for known SaaS prefer vendor Updatable Objects."))
manual("POL-08", "critical", T("Etiquetas dinámicas AWS: alta, cambio y baja", "Dynamic AWS tags: add, change and remove"),
       T("La política sigue a las instancias por etiqueta en tiempo casi real.", "The policy follows instances by tag in near real time."),
       T("Conector de nube con lectura de EC2 y regla con objeto dinámico por etiqueta.", "Cloud connector with EC2 read access and a rule with a dynamic tag object."),
       [("Crea un objeto dinámico «Environment=pro» y úsalo en una regla que permita un servicio.", "Create a dynamic object «Environment=pro» and use it in a rule allowing a service."),
        ("Lanza una instancia con esa etiqueta y mide cuánto tarda en estar permitida.", "Launch an instance with that tag and measure how long until it is allowed."),
        ("Cambia la etiqueta y mide cuánto tarda en dejar de estarlo; termina la instancia y verifica que su IP sale del objeto.", "Change the tag and measure how long until it stops being allowed; terminate the instance and check its IP leaves the object.")],
       T("Alta, cambio y baja reflejados sin reinstalar política, con tiempos medidos.", "Add, change and remove reflected without reinstalling the policy, with measured times."), EV_CONS,
       T("CloudGuard Controller actualiza los objetos de datacenter sin instalar política (intervalo de escaneo configurable, por defecto 30 s).", "CloudGuard Controller updates data center objects without a policy install (configurable scan interval, 30 s by default)."))
manual("POL-09", "high", T("Etiquetas entre cuentas, regiones y entornos", "Tags across accounts, regions and environments"),
       T("Los objetos por etiqueta funcionan con varias cuentas y regiones.", "Tag-based objects work across several accounts and regions."),
       T("Conector de nube con roles en varias cuentas (AssumeRole).", "Cloud connector with roles in several accounts (AssumeRole)."),
       [("Registra dos cuentas (o una cuenta en dos regiones) en el conector de nube con roles de solo lectura.", "Register two accounts (or one account in two regions) in the cloud connector with read-only roles."),
        ("Crea un objeto por etiqueta que incluya instancias de ambas y úsalo en una regla.", "Create a tag object including instances of both and use it in a rule."),
        ("Verifica que el objeto contiene las IP de ambas cuentas y que la regla aplica.", "Check that the object contains the IPs of both accounts and the rule applies.")],
       T("Un mismo objeto cubre cuentas y regiones.", "The same object covers accounts and regions."), EV_CONS,
       T("Un objeto de datacenter AWS por cuenta (rol STS) y grupos que los combinan.", "One AWS data center object per account (STS role) and groups combining them."))
manual("POL-13", "high", T("Reglas redundantes, ocultas y demasiado amplias", "Redundant, shadowed and overly broad rules"),
       T("Se detectan reglas que nunca aplican o que permiten de más.", "Rules that never apply or allow too much are detected."),
       T("Paquete de política con historial de tráfico.", "Policy package with traffic history."),
       [("Ejecuta el análisis de política del fabricante (reglas ocultas, redundantes, «any any»).", "Run the vendor policy analysis (shadowed, redundant, «any any» rules)."),
        ("Cruza el resultado con POL-14 (reglas sin aciertos).", "Cross-check with POL-14 (rules without hits)."),
        ("Documenta acciones: eliminar, acotar o justificar.", "Document actions: remove, narrow or justify.")],
       T("Lista de hallazgos con acción decidida para cada uno.", "List of findings with a decided action for each one."), EV_CONS,
       T("Policy Insights / Compliance blade (Best Practices) y hit count; evitar Any en servicio o destino en reglas Accept.", "Policy Insights / Compliance blade (Best Practices) and hit count; avoid Any as service or destination in Accept rules."))

# ------------------------------------------------------------------ APP
manual("APP-05", "critical", T("Línea base de tráfico anómalo", "Anomalous traffic baseline"),
       T("Se establece el comportamiento normal y se detectan desviaciones.", "Normal behaviour is established and deviations are detected."),
       T("Al menos una semana de registros.", "At least one week of logs."),
       [("Con una semana de registros, obtén el top de aplicaciones, destinos y volúmenes por entorno.", "With one week of logs, get the top applications, destinations and volumes per environment."),
        ("Genera una desviación (p. ej. transferencia grande nocturna a un destino nuevo con el kit).", "Generate a deviation (e.g. a large night transfer to a new destination with the kit)."),
        ("Verifica que aparece en informes/alertas de anomalías.", "Check it shows up in anomaly reports/alerts.")],
       T("La desviación se detecta y se puede investigar.", "The deviation is detected and can be investigated."), EV_CONS,
       T("SmartEvent / Infinity XDR/XPR con correlación de anomalías; vistas de Logs & Monitor por aplicación y volumen.", "SmartEvent / Infinity XDR/XPR with anomaly correlation; Logs & Monitor views by application and volume."))
manual("APP-06", "high", T("Picos, beaconing y conexiones anómalas", "Spikes, beaconing and anomalous connections"),
       T("Se detectan patrones de beaconing y picos de conexiones.", "Beaconing patterns and connection spikes are detected."),
       T("Anti-bot activo y correlación de eventos.", "Anti-bot enabled and event correlation."),
       [("Desde un cliente, genera una conexión periódica (cada 60 s, mismo tamaño) a un destino externo durante 1 h.", "From a client, generate a periodic connection (every 60 s, same size) to an external destination for 1 h."),
        ("Genera un pico de conexiones (p. ej. PERF-06) y un escaneo (IPS-02).", "Generate a connection spike (e.g. PERF-06) and a scan (IPS-02)."),
        ("Revisa qué eventos se generan y con qué severidad.", "Review which events are raised and their severity.")],
       T("Beaconing, pico y escaneo identificados con evidencia.", "Beaconing, spike and scan identified with evidence."), EV_CONS,
       T("Anti-Bot (comportamiento C&C) + SmartEvent/Infinity XDR; protección IPS «Port Scan».", "Anti-Bot (C&C behaviour) + SmartEvent/Infinity XDR; IPS «Port Scan» protection."))
manual("APP-08", "medium", T("Rate limiting y mitigación básica de abuso", "Rate limiting and basic abuse mitigation"),
       T("Se puede limitar la tasa de conexiones de un origen abusivo.", "The connection rate of an abusive source can be limited."),
       T("Capacidad de limitación de tasa en el firewall.", "Rate limiting capability on the firewall."),
       [("Configura un límite de conexiones por segundo por origen hacia el servidor de pruebas.", "Configure a connections-per-second limit per source towards the test server."),
        ("Lanza PERF-05 (CPS) desde un cliente y comprueba que la tasa se limita y queda registrado.", "Run PERF-05 (CPS) from a client and check the rate is limited and logged."),
        ("Retira el límite y repite para comparar.", "Remove the limit and repeat to compare.")],
       T("Tasa limitada al valor configurado y evento registrado.", "Rate limited to the configured value and event logged."), EV_CONS,
       T("Rate limiting con «fw samp add quota» (Accelerated DoS/Rate Limiting, sk112454) o protección IPS de inundación.", "Rate limiting with «fw samp add quota» (sk112454) or IPS flood protections."))

# ------------------------------------------------------------------ OBS
manual("OBS-03", "high", T("Auditoría de cambios API/UI/IaC", "Audit of API/UI/IaC changes"),
       T("Cada cambio de configuración queda registrado con quién, qué y cuándo.", "Every configuration change is logged with who, what and when."),
       T("Registro de auditoría de la gestión activo.", "Management audit log enabled."),
       [("Haz un cambio por la consola, otro por la API (p. ej. OPS-03) y otro por Terraform.", "Make a change from the console, another through the API (e.g. OPS-03) and another with Terraform."),
        ("Busca los tres en el registro de auditoría y compara los detalles (usuario/clave API, sesión, objeto, antes/después).", "Find the three in the audit log and compare the details (user/API key, session, object, before/after).")],
       T("Los tres cambios aparecen con autor, hora y detalle.", "The three changes appear with author, time and detail."), EV_CONS,
       T("Logs & Monitor → Audit; una clave API por automatización (nunca compartida) y nombre de sesión descriptivo.", "Logs & Monitor → Audit; one API key per automation (never shared) and a descriptive session name."))
manual("OBS-04", "critical", T("Exportación a SIEM y calidad de eventos", "SIEM export and event quality"),
       T("Los eventos llegan al SIEM completos, normalizados y a tiempo.", "Events reach the SIEM complete, normalized and on time."),
       T("SIEM o colector syslog accesible desde la gestión.", "SIEM or syslog collector reachable from the management."),
       [("Configura la exportación de registros (syslog CEF/LEEF o API) hacia el SIEM.", "Configure log export (syslog CEF/LEEF or API) to the SIEM."),
        ("Ejecuta OBS-01 y OBS-02 y localiza esos eventos en el SIEM.", "Run OBS-01 and OBS-02 and find those events in the SIEM."),
        ("Mide la latencia y compara campos con el registro original.", "Measure latency and compare fields with the original log.")],
       T("Eventos completos en el SIEM con latencia medida.", "Complete events in the SIEM with measured latency."), EV_CONS,
       T("Log Exporter (CEF, LEEF, JSON) o conectores de Infinity Events para SIEM; TLS hacia el colector.", "Log Exporter (CEF, LEEF, JSON) or Infinity Events SIEM connectors; TLS to the collector."))
manual("OBS-05", "high", T("Correlación con VPC/TGW Flow Logs", "Correlation with VPC/TGW Flow Logs"),
       T("Los registros del firewall se pueden cruzar con los flow logs de la nube.", "Firewall logs can be matched with cloud flow logs."),
       T("Flow logs activos en las VPC de spokes y en el TGW.", "Flow logs enabled on spoke VPCs and the TGW."),
       [("Activa VPC/TGW Flow Logs.", "Enable VPC/TGW Flow Logs."),
        ("Ejecuta NET-01 y busca la misma conexión (5-tupla y hora) en ambos registros.", "Run NET-01 and find the same connection (5-tuple and time) in both logs."),
        ("Comprueba que las IP de origen se conservan (sin NAT en el camino este-oeste).", "Check that source IPs are preserved (no NAT on the east-west path).")],
       T("La misma conexión se identifica en ambos registros.", "The same connection is identified in both logs."), EV_CONS,
       T("GWLB conserva la IP de origen; mantener los relojes en NTP para correlar.", "GWLB preserves the source IP; keep clocks on NTP to correlate."))
manual("OBS-06", "high", T("Captura de paquetes y diagnóstico de sesiones", "Packet capture and session diagnostics"),
       T("Se puede capturar y diagnosticar una sesión concreta.", "A given session can be captured and diagnosed."),
       T("Acceso administrativo a los gateways.", "Administrative access to the gateways."),
       [("Abre una captura filtrada por la IP de un cliente en el gateway.", "Start a capture filtered by a client IP on the gateway."),
        ("Ejecuta una comprobación del kit y descarga la captura.", "Run a kit check and download the capture."),
        ("Usa la herramienta de depuración de decisiones para ver qué regla aplicó.", "Use the decision debugging tool to see which rule applied.")],
       T("Captura y diagnóstico obtenidos sin interrumpir el servicio.", "Capture and diagnosis obtained without service interruption."), EV_CONS,
       T("«fw monitor -F» / «tcpdump», «fw ctl zdebug drop» y captura de paquetes en los registros (track-settings packet capture).", "«fw monitor -F» / «tcpdump», «fw ctl zdebug drop» and packet capture in logs (track-settings packet capture)."))
manual("OBS-07", "high", T("Visibilidad de activos, etiquetas, VPC, cuenta y región", "Asset, tag, VPC, account and region visibility"),
       T("Los registros y la consola muestran el contexto de nube del activo.", "Logs and console show the cloud context of the asset."),
       T("Conector de nube configurado.", "Cloud connector configured."),
       [("Consulta en la consola el inventario de activos importado de la nube.", "Check in the console the asset inventory imported from the cloud."),
        ("Abre un registro del kit y comprueba si muestra nombre de instancia, etiquetas, VPC, cuenta o región.", "Open a kit log and check whether it shows instance name, tags, VPC, account or region.")],
       T("Contexto de nube visible para investigar sin salir de la consola.", "Cloud context visible to investigate without leaving the console."), EV_CONS,
       T("Objetos de datacenter de CloudGuard Controller en reglas y registros; CloudGuard CNAPP para inventario completo.", "CloudGuard Controller data center objects in rules and logs; CloudGuard CNAPP for full inventory."))
manual("OBS-09", "high", T("Registros bajo presión y retención", "Logs under load and retention"),
       T("No se pierden registros con carga alta y la retención cumple lo requerido.", "No logs are lost under high load and retention meets the requirement."),
       T("Carga de PERF-05/PERF-06 disponible.", "PERF-05/PERF-06 load available."),
       [("Lanza PERF-05 (miles de conexiones nuevas) y cuenta las conexiones generadas.", "Run PERF-05 (thousands of new connections) and count the connections generated."),
        ("Cuenta los registros correspondientes en la consola y calcula el porcentaje.", "Count the matching logs in the console and compute the percentage."),
        ("Revisa la política de retención contratada/configurada.", "Review the contracted/configured retention policy.")],
       T("≥ 99 % de registros y retención documentada.", "≥ 99 % of logs and documented retention."), EV_CONS,
       T("Smart-1 Cloud: retención según suscripción; registros acumulados en el gateway si se pierde la conexión con la gestión.", "Smart-1 Cloud: retention per subscription; logs buffered on the gateway if the management connection is lost."))
manual("OBS-10", "medium", T("Telemetría Syslog/SNMP/NetFlow", "Syslog/SNMP/NetFlow telemetry"),
       T("El firewall exporta telemetría estándar.", "The firewall exports standard telemetry."),
       T("Colectores de syslog/SNMP/NetFlow.", "Syslog/SNMP/NetFlow collectors."),
       [("Configura en los gateways el envío de SNMP (v3), NetFlow/IPFIX y syslog del sistema.", "Configure SNMP (v3), NetFlow/IPFIX and system syslog on the gateways."),
        ("Comprueba en los colectores que llegan datos y que son coherentes con la carga del kit.", "Check in the collectors that data arrives and matches the kit load.")],
       T("Telemetría recibida y coherente.", "Telemetry received and consistent."), EV_CONS,
       T("Gaia: SNMPv3, NetFlow export y syslog remoto; en gateways de autoescalado se aplican por script de inicio o plantilla de CME.", "Gaia: SNMPv3, NetFlow export and remote syslog; on autoscaling gateways apply them through the bootstrap script or CME template."))
manual("OBS-11", "medium", T("Informes de investigación y búsqueda por filtros", "Investigation reports and filtered search"),
       T("Se encuentra rápido lo ocurrido con un activo o ataque.", "What happened with an asset or attack is found quickly."),
       T("Registros de una ejecución completa del kit.", "Logs of a full kit run."),
       [("Tras una ejecución completa, busca por IP de origen, protección y franja horaria.", "After a full run, search by source IP, protection and time range."),
        ("Genera un informe de amenazas del periodo y exporta.", "Generate a threat report for the period and export it.")],
       T("Búsquedas en segundos e informe exportable.", "Searches in seconds and exportable report."), EV_CONS,
       T("Logs & Monitor (consultas guardadas), informes de Infinity Events/SmartEvent.", "Logs & Monitor (saved queries), Infinity Events/SmartEvent reports."))

# ------------------------------------------------------------------ HA
manual("HA-06", "high", T("Actualización blue/green y mantenimiento", "Blue/green upgrade and maintenance"),
       T("Se actualiza la versión de los gateways sin cortar el servicio.", "Gateway versions are upgraded without service interruption."),
       T("Plantilla de lanzamiento versionada del grupo de autoescalado.", "Versioned launch template of the Auto Scaling group."),
       [("Con las sondas de HA en marcha, cambia la imagen/versión en la plantilla del grupo.", "With the HA probes running, change the image/version in the group template."),
        ("Lanza un instance refresh (o un grupo nuevo en paralelo) y deja que los gateways se sustituyan de uno en uno.", "Start an instance refresh (or a new parallel group) and let gateways be replaced one at a time."),
        ("Mide interrupciones y confirma la versión y política de los nuevos gateways.", "Measure interruptions and confirm version and policy of the new gateways.")],
       T("Sustitución progresiva sin interrupción por encima del umbral de HA.", "Progressive replacement without interruption above the HA threshold."), EV_CONS,
       T("Instance refresh con «minimum healthy 100 %» o grupo blue/green; CME aprovisiona los nuevos gateways con la misma plantilla.", "Instance refresh with «minimum healthy 100 %» or blue/green group; CME provisions the new gateways with the same template."))
manual("HA-07", "high", T("Resiliencia ante fallo de DNS o del plano de control", "Resilience to DNS or control plane failure"),
       T("Si la gestión o el DNS fallan, el tráfico sigue inspeccionado con la última política.", "If the management or DNS fails, traffic is still inspected with the last policy."),
       T("Posibilidad de cortar la conexión gateway–gestión de forma controlada.", "Ability to cut the gateway–management connection in a controlled way."),
       [("Corta temporalmente la conexión de los gateways con la gestión (regla de salida o NACL).", "Temporarily cut the gateways' connection to the management (egress rule or NACL)."),
        ("Ejecuta un lote corto del kit (NET-01, IPS-01, TLS-01) y verifica decisiones y que los registros se acumulan.", "Run a short kit batch (NET-01, IPS-01, TLS-01) and check decisions and that logs are buffered."),
        ("Restaura y comprueba que llegan los registros pendientes; repite cortando el DNS de los gateways.", "Restore and check the pending logs arrive; repeat cutting the gateways' DNS.")],
       T("Política aplicada sin gestión ni DNS; registros recuperados.", "Policy enforced without management or DNS; logs recovered."), EV_CONS,
       T("El gateway conserva la política local y acumula registros; las reglas por dominio dependen del DNS del gateway (usar resolvedores redundantes).", "The gateway keeps the local policy and buffers logs; domain rules depend on the gateway DNS (use redundant resolvers)."))
manual("HA-08", "medium", T("Recuperación ante desastre y restauración", "Disaster recovery and restore"),
       T("Se puede reconstruir el despliegue completo desde código y copias.", "The whole deployment can be rebuilt from code and backups."),
       T("Infraestructura como código y copia de la gestión.", "Infrastructure as code and management backup."),
       [("Destruye el plano de inspección (o despliega en otra región) con el código de infraestructura.", "Destroy the inspection tier (or deploy in another region) with the infrastructure code."),
        ("Recrea, deja que la gestión aprovisione los gateways e instale la política.", "Recreate, let the management provision the gateways and install the policy."),
        ("Ejecuta el lote completo y mide el tiempo total (RTO).", "Run the full batch and measure the total time (RTO).")],
       T("Entorno recuperado y con los mismos resultados; RTO medido.", "Environment recovered with the same results; RTO measured."), EV_CONS,
       T("Terraform de los módulos oficiales + política como código; Smart-1 Cloud con copias gestionadas por el servicio.", "Terraform with the official modules + policy as code; Smart-1 Cloud with service-managed backups."))

# ------------------------------------------------------------------ OPS
manual("OPS-02", "critical", T("Administración RBAC/SSO/MFA", "RBAC/SSO/MFA administration"),
       T("Los administradores entran con SSO y MFA y con permisos mínimos por perfil.", "Administrators log in with SSO and MFA and least-privilege profiles."),
       T("Proveedor de identidad corporativo (SAML/OIDC).", "Corporate identity provider (SAML/OIDC)."),
       [("Integra el portal/gestión con el IdP corporativo por SAML y exige MFA.", "Integrate the portal/management with the corporate IdP over SAML and require MFA."),
        ("Crea un perfil de solo lectura y otro de operador de políticas; prueba que cada uno solo puede lo suyo.", "Create a read-only profile and a policy operator profile; test each can only do its part."),
        ("Verifica en auditoría el usuario real de cada acción.", "Check the audit log shows the real user of each action.")],
       T("SSO+MFA obligatorios y permisos separados verificados.", "SSO+MFA enforced and separated permissions verified."), EV_CONS,
       T("Infinity Portal con SSO (SAML) y MFA; perfiles de permisos por capa y por dominio.", "Infinity Portal with SSO (SAML) and MFA; permission profiles per layer and domain."))
manual("OPS-04", "high", T("Gestión centralizada multi-cuenta/tenant", "Centralized multi-account/tenant management"),
       T("Una consola gestiona varias cuentas y entornos con separación.", "One console manages several accounts and environments with separation."),
       T("Al menos dos cuentas o entornos.", "At least two accounts or environments."),
       [("Registra varias cuentas en el conector de autoescalado/nube.", "Register several accounts in the autoscaling/cloud connector."),
        ("Asigna paquetes de política o dominios distintos y comprueba que un administrador de uno no ve el otro.", "Assign different policy packages or domains and check an administrator of one cannot see the other.")],
       T("Gestión central con separación verificada.", "Central management with verified separation."), EV_CONS,
       T("CME con varias cuentas/plantillas; Multi-Domain en Smart-1 Cloud si se necesita separación por tenant.", "CME with several accounts/templates; Multi-Domain on Smart-1 Cloud when tenant separation is needed."))
manual("OPS-05", "high", T("Versiones, copia y vuelta atrás", "Versions, backup and rollback"),
       T("Se puede volver a una versión anterior de política o de software.", "A previous policy or software version can be restored."),
       T("Historial de revisiones de política.", "Policy revision history."),
       [("Publica e instala un cambio y luego vuelve a la revisión anterior desde el historial.", "Publish and install a change and then revert to the previous revision from the history."),
        ("Verifica con el kit que el comportamiento vuelve al anterior.", "Verify with the kit that the behaviour returns to the previous one.")],
       T("Vuelta atrás completa en minutos y verificada.", "Full rollback in minutes, verified."), EV_CONS,
       T("Installation History → «Install specific version»; las revisiones se conservan automáticamente.", "Installation History → «Install specific version»; revisions are kept automatically."))
manual("OPS-06", "high", T("Experiencia operativa en alta/baja/modificación de reglas", "Operational experience adding/removing/changing rules"),
       T("Las tareas habituales son rápidas y con poco riesgo de error.", "Routine tasks are quick and low-risk."),
       T("Operadores del cliente con acceso a la consola.", "Customer operators with console access."),
       [("Un operador del cliente da de alta, modifica y elimina una regla con la consola, cronometrando cada tarea.", "A customer operator adds, changes and removes a rule in the console, timing each task."),
        ("Comprueba las validaciones (conflictos, objetos duplicados) y la vista previa de cambios antes de publicar.", "Check validations (conflicts, duplicate objects) and the change preview before publishing.")],
       T("Tiempos y valoración de los operadores documentados.", "Times and operator assessment documented."), EV_CONS,
       T("Sesiones con vista de cambios, búsqueda de objetos en uso («Where used») y secciones en las capas (como las que crea el kit).", "Sessions with change view, «Where used» object search and sections in the layers (as the kit creates)."))
manual("OPS-07", "critical", T("Gobierno de excepciones y trazabilidad ITSM", "Exception governance and ITSM traceability"),
       T("Cada excepción se vincula a un ticket y se revisa periódicamente.", "Every exception is linked to a ticket and reviewed periodically."),
       T("Herramienta ITSM corporativa.", "Corporate ITSM tool."),
       [("Crea una excepción indicando el número de ticket en el comentario/sesión.", "Create an exception with the ticket number in the comment/session."),
        ("Comprueba que desde el ticket se llega a la regla y viceversa.", "Check you can go from the ticket to the rule and back."),
        ("Lista las excepciones caducadas o sin ticket.", "List expired exceptions or those without ticket.")],
       T("Todas las excepciones trazables y revisables.", "All exceptions traceable and reviewable."), EV_CONS,
       T("Campo de ticket en la sesión/regla, integración ITSM por API y caducidad con objetos de tiempo.", "Ticket field in the session/rule, ITSM integration through the API and expiry with time objects."))
manual("OPS-08", "high", T("Etiquetado, descubrimiento continuo y alta de políticas", "Tagging, continuous discovery and policy onboarding"),
       T("Los activos nuevos se descubren y reciben política según su etiqueta.", "New assets are discovered and get policy according to their tag."),
       T("Convención de etiquetas (entorno, aplicación, criticidad).", "Tag convention (environment, application, criticality)."),
       [("Define la convención de etiquetas y crea objetos dinámicos para cada valor.", "Define the tag convention and create dynamic objects for each value."),
        ("Despliega un activo nuevo etiquetado y comprueba que recibe la política esperada (ver POL-08).", "Deploy a new tagged asset and check it gets the expected policy (see POL-08)."),
        ("Detecta activos sin etiqueta y su tratamiento por defecto (denegación).", "Detect untagged assets and their default handling (deny).")],
       T("Alta automática por etiqueta; activos sin etiqueta denegados.", "Automatic onboarding by tag; untagged assets denied."), EV_CONS,
       T("CloudGuard Controller + regla de limpieza en Drop con registro.", "CloudGuard Controller + cleanup rule in Drop with logging."))
manual("OPS-09", "high", T("Control de credenciales y secretos de gestión", "Management credentials and secrets control"),
       T("Las credenciales de gestión y automatización están protegidas y rotadas.", "Management and automation credentials are protected and rotated."),
       T("Gestor de secretos corporativo.", "Corporate secrets manager."),
       [("Inventaria claves API, credenciales de nube y claves SIC/aprovisionamiento.", "Inventory API keys, cloud credentials and SIC/provisioning keys."),
        ("Comprueba que se guardan en un gestor de secretos, sin texto plano en código ni repositorios.", "Check they are stored in a secrets manager, never in plain text in code or repositories."),
        ("Rota una clave API y verifica que la automatización sigue funcionando.", "Rotate an API key and check the automation keeps working.")],
       T("Sin secretos en claro y rotación probada.", "No clear-text secrets and rotation tested."), EV_CONS,
       T("Una clave API por integración con permisos mínimos; roles STS (sin claves de larga duración) para el conector de nube.", "One API key per integration with least privileges; STS roles (no long-lived keys) for the cloud connector."))

# ------------------------------------------------------------------ INT
manual("INT-01", "medium", T("Integración con Entra ID para acceso administrativo", "Entra ID integration for administrative access"),
       T("Los administradores se autentican con Entra ID.", "Administrators authenticate with Entra ID."),
       T("Inquilino de Entra ID con aplicación empresarial SAML.", "Entra ID tenant with a SAML enterprise application."),
       [("Crea la aplicación SAML en Entra ID y configúrala como IdP del portal de gestión.", "Create the SAML application in Entra ID and configure it as IdP of the management portal."),
        ("Asigna grupos a perfiles de permisos y prueba el acceso con MFA condicional.", "Map groups to permission profiles and test access with conditional MFA.")],
       T("Acceso con Entra ID y perfiles por grupo.", "Access with Entra ID and group-based profiles."), EV_CONS,
       T("Infinity Portal → Identity providers → Entra ID (SAML).", "Infinity Portal → Identity providers → Entra ID (SAML)."))
manual("INT-02", "medium", T("Integración PingID/PingOne para administradores", "PingID/PingOne integration for administrators"),
       T("Los administradores se autentican con PingOne.", "Administrators authenticate with PingOne."),
       T("Entorno PingOne con aplicación SAML.", "PingOne environment with a SAML application."),
       [("Configura PingOne como IdP SAML del portal de gestión.", "Configure PingOne as SAML IdP of the management portal."),
        ("Prueba el acceso con MFA de PingID y el mapeo de grupos.", "Test access with PingID MFA and group mapping.")],
       T("Acceso con PingOne y MFA.", "Access with PingOne and MFA."), EV_CONS,
       T("Infinity Portal admite cualquier IdP SAML 2.0.", "Infinity Portal supports any SAML 2.0 IdP."))
manual("INT-03", "medium", T("Alertas y casos hacia ServiceNow", "Alerts and cases to ServiceNow"),
       T("Los eventos críticos abren casos en el ITSM.", "Critical events open cases in the ITSM."),
       T("Instancia ITSM con API.", "ITSM instance with API."),
       [("Configura la integración de eventos → ITSM (webhook o conector).", "Configure the events → ITSM integration (webhook or connector)."),
        ("Ejecuta IPS-01 y comprueba que se abre un caso con los datos del evento.", "Run IPS-01 and check a case is opened with the event data.")],
       T("Caso creado automáticamente con contexto.", "Case created automatically with context."), EV_CONS,
       T("Infinity Events / Playblocks con acciones hacia ServiceNow.", "Infinity Events / Playblocks with actions to ServiceNow."))
manual("INT-04", "high", T("Interoperabilidad con herramientas SOC", "Interoperability with SOC tools"),
       T("El SOC consume eventos y puede actuar (bloquear) desde sus herramientas.", "The SOC consumes events and can act (block) from its tools."),
       T("SIEM/SOAR del SOC.", "SOC SIEM/SOAR."),
       [("Envía eventos al SIEM (OBS-04).", "Send events to the SIEM (OBS-04)."),
        ("Desde el SOAR, añade un indicador por API (como IPS-10) y verifica el bloqueo.", "From the SOAR, add an indicator through the API (as IPS-10) and verify the block.")],
       T("Ciclo detectar → bloquear automatizado.", "Automated detect → block loop."), EV_CONS,
       T("API de gestión (indicadores, objetos dinámicos), Log Exporter y conectores SOAR.", "Management API (indicators, dynamic objects), Log Exporter and SOAR connectors."))
manual("INT-05", "medium", T("Contenedores/Kubernetes y servicios dinámicos", "Containers/Kubernetes and dynamic services"),
       T("La política sigue a cargas dinámicas (pods, servicios).", "The policy follows dynamic workloads (pods, services)."),
       OUT_LAB("necesita un clúster EKS en un spoke.", "needs an EKS cluster in a spoke."),
       [("Despliega un clúster con servicios etiquetados en un spoke.", "Deploy a cluster with labeled services in a spoke."),
        ("Usa objetos dinámicos por namespace/etiqueta en la política y escala los pods.", "Use dynamic objects by namespace/label in the policy and scale the pods."),
        ("Verifica que las reglas siguen a los pods.", "Check the rules follow the pods.")],
       T("Política aplicada a cargas dinámicas sin tocar reglas.", "Policy applied to dynamic workloads without editing rules."), EV_CONS,
       T("CloudGuard Controller para Kubernetes y CloudGuard CNAPP para seguridad dentro del clúster.", "CloudGuard Controller for Kubernetes and CloudGuard CNAPP for in-cluster security."), scope="out_of_lab")
manual("INT-06", "medium", T("Mismo control en varias regiones o nubes", "Same control across regions or clouds"),
       T("Una política común se aplica en varias regiones o nubes.", "A common policy is enforced across regions or clouds."),
       OUT_LAB("necesita una segunda región o nube.", "needs a second region or cloud."),
       [("Despliega el mismo patrón en otra región/nube con el mismo código.", "Deploy the same pattern in another region/cloud with the same code."),
        ("Instala la misma política y ejecuta el lote del kit en ambas.", "Install the same policy and run the kit batch in both."),
        ("Compara los resultados con el informe comparativo del portal.", "Compare the results with the portal comparison report.")],
       T("Mismos resultados en ambas ubicaciones.", "Same results in both locations."), EV_CONS,
       T("Una gestión y una política compartida; plantillas CME por región.", "One management and a shared policy; CME templates per region."), scope="out_of_lab")

# ------------------------------------------------------------------ COST
COST_HOW = T("Calculadora de AWS + consumo real (Cost Explorer por etiqueta) del laboratorio durante la POC.", "AWS calculator + actual consumption (Cost Explorer by tag) of the lab during the POC.")
manual("COST-01", "high", T("Coste fijo de plataforma y licencias", "Fixed platform and licence cost"),
       T("Se conoce el coste fijo mensual de la solución.", "The fixed monthly cost of the solution is known."), T("Precios de licencia y de la gestión.", "Licence and management prices."),
       [("Suma licencias (BYOL/PAYG), gestión y soporte para el tamaño mínimo (2 gateways en 2 AZ).", "Add licences (BYOL/PAYG), management and support for the minimum size (2 gateways in 2 AZs)."),
        ("Añade el coste fijo de AWS: instancias, GWLB, endpoints y attachments del TGW por hora.", "Add the fixed AWS cost: instances, GWLB, endpoints and TGW attachments per hour.")],
       T("Coste fijo mensual desglosado.", "Itemized fixed monthly cost."), EV_CONS,
       T("Licenciamiento por vCPU o PAYG en Marketplace; Smart-1 Cloud como servicio.", "Per-vCPU licensing or Marketplace PAYG; Smart-1 Cloud as a service.") )
manual("COST-02", "high", T("Coste variable por GB y rutas AWS", "Variable cost per GB and AWS routes"),
       T("Se conoce el coste por GB inspeccionado según el camino.", "The cost per inspected GB is known for each path."), T("Volúmenes de tráfico estimados.", "Estimated traffic volumes."),
       [("Para este-oeste y salida, suma procesamiento de TGW, GWLB endpoint, GWLB, NAT y transferencia entre AZ por GB.", "For east-west and egress, add TGW, GWLB endpoint, GWLB, NAT and cross-AZ transfer processing per GB."),
        ("Contrasta con el consumo real tras una ejecución de PERF.", "Compare with the actual consumption after a PERF run.")],
       T("Coste por GB por camino.", "Cost per GB per path."), EV_CONS, COST_HOW)
manual("COST-03", "high", T("Coste incremental de IPS/TLS/AV", "Incremental cost of IPS/TLS/AV"),
       T("Se estima el coste de activar las capacidades avanzadas.", "Estimates the cost of enabling advanced capabilities."), T("Resultados de PERF-01, PERF-02 y PERF-08.", "PERF-01, PERF-02 and PERF-08 results."),
       [("Compara el caudal y la CPU con política L3/L4 (PERF-01) y con perfil completo (PERF-02/PERF-08).", "Compare throughput and CPU with L3/L4 policy (PERF-01) and full profile (PERF-02/PERF-08)."),
        ("Traduce la diferencia en número de gateways (y coste) para el tráfico previsto.", "Translate the difference into gateways (and cost) for the expected traffic.")],
       T("Coste incremental justificado con medidas.", "Incremental cost backed by measurements."), EV_CONS,
       T("Dimensionar con el perfil real (Optimized/Strict) y bypass TLS de categorías sensibles y de alto volumen de confianza.", "Size with the real profile (Optimized/Strict) and TLS bypass of sensitive and trusted high-volume categories."))
manual("COST-04", "medium", T("Coste de redundancia AZ y escalado", "Cost of AZ redundancy and scaling"),
       T("Se conoce el coste de la alta disponibilidad y del escalado.", "The cost of high availability and scaling is known."), T("Resultados de HA-02 y HA-05.", "HA-02 and HA-05 results."),
       [("Calcula el coste del mínimo redundante (n+1 por AZ) y de cada gateway adicional por escalado.", "Compute the cost of the redundant minimum (n+1 per AZ) and of each extra gateway from scaling."),
        ("Usa los umbrales de escalado observados para estimar horas de escalado al mes.", "Use the observed scaling thresholds to estimate scaled hours per month.")],
       T("Coste de HA y de picos documentado.", "HA and peak cost documented."), EV_CONS, COST_HOW)
manual("COST-05", "high", T("Coste de administración, soporte y registros", "Administration, support and log cost"),
       T("Se estima el esfuerzo operativo y el coste de registros.", "Estimates operational effort and log cost."), T("Volumen de registros de una ejecución completa.", "Log volume of a full run."),
       [("Mide los registros por día de una ejecución y extrapola al tráfico real.", "Measure logs per day of a run and extrapolate to the real traffic."),
        ("Estima horas de operación al mes (OPS-06) y coste de retención/SIEM.", "Estimate operating hours per month (OPS-06) and retention/SIEM cost.")],
       T("Coste operativo anual estimado.", "Estimated yearly operating cost."), EV_CONS,
       T("Retención incluida en Smart-1 Cloud según plan; registrar Accept solo donde aporta (secciones con registro selectivo).", "Retention included in Smart-1 Cloud per plan; log Accepts only where useful (sections with selective logging)."))

# ------------------------------------------------------------------ WAF
manual("WAF-02", "medium", T("Excepciones, ajuste y actualización de políticas WAF", "WAF policy exceptions, tuning and updates"),
       T("El WAF se ajusta sin abrir huecos y se actualiza solo.", "The WAF is tuned without opening gaps and updates itself."),
       OUT_LAB("necesita una aplicación web publicada detrás de un WAF.", "needs a web application published behind a WAF."),
       [("Publica una aplicación de prueba con WAF en modo aprendizaje y luego en prevención.", "Publish a test application with WAF in learning and then prevention mode."),
        ("Genera un falso positivo y crea una excepción acotada (parámetro/URL).", "Generate a false positive and create a narrow exception (parameter/URL)."),
        ("Repite los ataques de WAF-01 y comprueba que siguen bloqueados.", "Repeat the WAF-01 attacks and check they are still blocked.")],
       T("Excepción acotada y ataques bloqueados.", "Narrow exception and attacks blocked."), EV_CONS,
       T("CloudGuard WAF (motor de aprendizaje contextual, sin firmas que mantener) con excepciones por parámetro.", "CloudGuard WAF (contextual machine-learning engine, no signatures to maintain) with per-parameter exceptions."), scope="out_of_lab")
manual("WAF-03", "medium", T("Protección de API / HTTP y TLS", "API / HTTP and TLS protection"),
       T("Las API publicadas se protegen por esquema y contra abuso.", "Published APIs are protected by schema and against abuse."),
       OUT_LAB("necesita una API publicada detrás de un WAF.", "needs an API published behind a WAF."),
       [("Publica una API con su esquema OpenAPI detrás del WAF.", "Publish an API with its OpenAPI schema behind the WAF."),
        ("Envía peticiones fuera de esquema, inyecciones en JSON y abuso de tasa.", "Send out-of-schema requests, JSON injections and rate abuse."),
        ("Comprueba bloqueos y registros.", "Check blocks and logs.")],
       T("Peticiones fuera de esquema y abuso bloqueados.", "Out-of-schema requests and abuse blocked."), EV_CONS,
       T("CloudGuard WAF con validación de esquema OpenAPI y limitación de tasa.", "CloudGuard WAF with OpenAPI schema validation and rate limiting."), scope="out_of_lab")

# ------------------------------------------------------------------ THR
manual("THR-04", "medium", T("Emulación/sandbox de fichero de prueba", "Emulation/sandbox of a test file"),
       T("Los ficheros desconocidos se analizan en sandbox antes de entregarse.", "Unknown files are analysed in a sandbox before delivery."),
       OUT_LAB("necesita la capacidad de sandbox (emulación) licenciada y un fichero de prueba del fabricante.", "needs the licensed sandbox (emulation) capability and a vendor test file."),
       [("Activa la emulación en el perfil de amenazas en modo Prevent (retener el fichero hasta el veredicto).", "Enable emulation in the threat profile in Prevent mode (hold the file until the verdict)."),
        ("Descarga desde un cliente un fichero de prueba de emulación del fabricante y un documento benigno nuevo.", "Download from a client a vendor emulation test file and a new benign document."),
        ("Comprueba el veredicto, el tiempo de entrega y el informe de emulación.", "Check the verdict, delivery time and the emulation report.")],
       T("Fichero malicioso bloqueado con informe; benigno entregado con tiempo medido.", "Malicious file blocked with a report; benign file delivered with measured time."), EV_CONS,
       T("Threat Emulation (ThreatCloud) en Prevent + Threat Extraction para documentos (entrega inmediata de una copia limpia).", "Threat Emulation (ThreatCloud) in Prevent + Threat Extraction for documents (immediate delivery of a clean copy)."),
       scope="out_of_lab")

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog_bp.py"), encoding="utf-8").read())
