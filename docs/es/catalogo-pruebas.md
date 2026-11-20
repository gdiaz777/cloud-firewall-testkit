# Catálogo de pruebas

_English: [test-catalog.md](../en/test-catalog.md)_

Generado desde `catalog/tests.json`. Cada caso indica su objetivo, los requisitos de política, las comprobaciones automáticas y, aparte, notas de cómo lo resuelve Check Point (en el portal y los informes solo aparecen si la solución probada es Check Point).

## Resumen

| Dominio | Casos | Comprobaciones |
|---|---:|---:|
| [NET · Arquitectura y enrutamiento](#net) | 5 | 16 |
| [POL · Políticas y segmentación](#pol) | 8 | 20 |
| [IPS · Prevención de intrusiones](#ips) | 9 | 40 |
| [THR · Malware y amenazas](#thr) | 4 | 27 |
| [TLS · Inspección y cifrado TLS](#tls) | 10 | 38 |
| [APP · Control L7 y anomalías](#app) | 5 | 28 |
| [DLP · Prevención de fuga de datos](#dlp) | 3 | 13 |
| [WAF · Protección web complementaria](#waf) | 1 | 4 |

<a id="net"></a>
## NET · Arquitectura y enrutamiento

### NET-01 · Inspección este-oeste entre VPC

**Prioridad:** Crítica  
**Objetivo:** Los flujos entre entornos atraviesan el firewall en ambos sentidos y se permiten o deniegan según la matriz.  
**Requisitos de política:** Regla que permite ICMP, HTTP y HTTPS hacia el entorno del servidor y deniega el resto.  
_Notas de Check Point: El tráfico entre VPC pasa por el Transit Gateway hacia la VPC de inspección (GWLBe) y el Gateway Load Balancer lo entrega a Check Point Cloud Firewall. Cada decisión queda registrada con la regla que la tomó._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-01.1 | ICMP echo al servidor | Ping desde la IP de workload. | Permitido | Firewall |
| NET-01.2 | HTTP tcp/80 al servidor | Servicio publicado. | Permitido | Firewall |
| NET-01.3 | HTTPS tcp/443 al servidor | Servicio publicado e inspeccionado. | Permitido | Firewall |
| NET-01.4 | SSH tcp/22 al servidor | El servidor escucha, pero la política no lo permite. | Bloqueado | Firewall |
| NET-01.5 | Telnet tcp/23 al servidor | Protocolo inseguro con servicio a la escucha. | Bloqueado | Firewall |
| NET-01.6 | tcp/8080 al servidor | HTTP alternativo no autorizado. | Bloqueado | Firewall |
| NET-01.7 | RDP tcp/3389 al servidor | Administración remota no autorizada. | Bloqueado | Firewall |

### NET-03 · Salida norte-sur a Internet

**Prioridad:** Crítica  
**Objetivo:** La salida a Internet se inspecciona de forma centralizada; solo pasa lo previsto.  
**Requisitos de política:** Capa de salida que permite solo HTTP, HTTPS y DNS.  
_Notas de Check Point: Salida centralizada (spoke → TGW → inspección → VPC de salida con NAT Gateway). En el firewall, una capa en línea permite HTTP/HTTPS (con firma de protocolo) y DNS, y deniega el resto._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-03.1 | HTTP a Internet | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall |
| NET-03.2 | HTTPS a Internet | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall / TLS inspection |
| NET-03.3 | DNS UDP a resolvedor público | Consulta DNS directa: servicio permitido. | Permitido | Firewall |
| NET-03.4 | SMTP tcp/25 a Internet | Puerto no web hacia Internet. | Bloqueado | Firewall |
| NET-03.5 | NTP UDP/123 a Internet | UDP distinto de DNS no está permitido. | Bloqueado | Firewall |
| NET-03.6 | IP pública de salida | Muestra la IP pública con la que se sale (NAT centralizado). | Permitido | Architecture |

### NET-05 · Simetría de enrutamiento stateful entre AZ

**Prioridad:** Crítica  
**Objetivo:** Ida y vuelta de un flujo entre AZ distintas llegan al mismo contexto stateful.  
**Requisitos de política:** Pares de entornos en AZ distintas (configuración) con HTTP permitido entre ellos.  
_Notas de Check Point: Con el attachment de inspección en appliance mode, ambos sentidos usan el mismo GWLBe y el GWLB los entrega al mismo gateway; la sesión no se rompe._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-05.1 | Sesión TCP de 20 s con el par de otra AZ | Conexión HTTP persistente con 10 peticiones en 20 s: con asimetría, el firewall descartaría la vuelta. | Permitido | Architecture |

### NET-07 · Segmentación entre producción y no producción

**Prioridad:** Crítica  
**Objetivo:** No hay tráfico entre producción y no producción salvo las excepciones aprobadas.  
**Requisitos de política:** Roles prod_envs y nonprod_envs y la matriz de segmentación.  
_Notas de Check Point: Los entornos se definen por CIDR y reglas explícitas bloquean producción ↔ no producción en ambos sentidos._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-07.1 | Matriz producción ↔ no producción | Matriz de segmentación configurada: desde este entorno hacia los demás se prueban ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 e iperf3, y se compara con lo permitido. | Según matriz | Firewall |

### NET-13 · MTU, fragmentación y GENEVE

**Prioridad:** Alta  
**Objetivo:** No hay agujeros negros por MTU; el tamaño máximo útil queda medido.  
**Requisitos de política:** ICMP permitido hacia el servidor.  
_Notas de Check Point: GWLB encapsula en GENEVE y admite MTU de 8.500 bytes. Se mide el mayor paquete que pasa sin fragmentar._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-13.1 | MTU efectiva hacia el servidor | Ping con DF de 1.472 a 8.472 bytes. Criterio: ≥ 1.472. | Medida | Architecture |

<a id="pol"></a>
## POL · Políticas y segmentación

### POL-01 · Allow/deny stateful y denegación por defecto

**Prioridad:** Crítica  
**Objetivo:** Solo pasan las 5-tuplas autorizadas; el resto se descarta y se registra.  
**Requisitos de política:** Lista blanca hacia el servidor y cleanup.  
_Notas de Check Point: Política stateful con lista blanca y regla de limpieza final (Drop + Log)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-01.1 | tcp/80 autorizado | 5-tupla autorizada. | Permitido | Firewall |
| POL-01.2 | tcp/443 autorizado | 5-tupla autorizada. | Permitido | Firewall |
| POL-01.3 | tcp/22 no autorizado | Mismo origen y destino, puerto no autorizado. | Bloqueado | Firewall |
| POL-01.4 | tcp/5202 no autorizado | Puerto contiguo a una excepción. | Bloqueado | Firewall |

### POL-02 · Excepciones granulares por 5-tupla

**Prioridad:** Crítica  
**Objetivo:** Una excepción solo abre el flujo indicado; puertos vecinos siguen bloqueados.  
**Requisitos de política:** Regla que permita solo el puerto de excepción configurado.  
_Notas de Check Point: Regla de excepción para un único puerto (por defecto iperf3 tcp/5201) entre entornos._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-02.1 | Puerto exceptuado | Flujo exceptuado. | Permitido | Firewall |
| POL-02.2 | Puerto vecino inferior | No debe quedar abierto. | Bloqueado | Firewall |
| POL-02.3 | Puerto vecino superior | No debe quedar abierto. | Bloqueado | Firewall |

### POL-05 · Reglas por FQDN

**Prioridad:** Crítica  
**Objetivo:** La decisión se toma por el dominio, no por la IP.  
**Requisitos de política:** Sitio personalizado con el FQDN bloqueado configurado.  
_Notas de Check Point: Sitio personalizado de URL Filtering: se decide por Host (HTTP) y SNI/certificado (HTTPS). Por defecto www.example.org (bloqueado) y www.example.com (permitido) comparten IP._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-05.1 | FQDN permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering |
| POL-05.2 | FQDN bloqueado (HTTP) | Mismo hosting e IP: solo se bloquea si la decisión es por nombre. | Bloqueado | URL Filtering |
| POL-05.3 | FQDN bloqueado (HTTPS) | En HTTPS se decide por SNI/certificado. | Bloqueado | URL Filtering / TLS inspection |

### POL-07 · Fallos de DNS

**Prioridad:** Crítica  
**Objetivo:** Un fallo de resolución no abre conectividad.  
**Requisitos de política:** Ninguno.  
_Notas de Check Point: Sin resolución no hay flujo y la política sigue en denegación por defecto._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-07.1 | Nombre inexistente (NXDOMAIN) | curl a un nombre .invalid. | Sin flujo | Firewall |

### POL-10 · Precedencia de reglas

**Prioridad:** Crítica  
**Objetivo:** El orden de evaluación es determinista y la regla efectiva queda registrada.  
**Requisitos de política:** Roles precedence_clients y precedence_target, y la regla de excepción por encima de la de bloqueo.  
_Notas de Check Point: La política se evalúa de arriba abajo: una regla de excepción por encima de la de segmentación gana para su servicio; el resto lo decide la segmentación._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-10.1 | Servicio exceptuado hacia el destino bloqueado (solo desde el papel `precedence_clients`) | La regla de excepción está antes que la de bloqueo. | Permitido | Firewall |
| POL-10.2 | HTTP hacia el destino bloqueado (solo desde el papel `precedence_clients`) | Sin regla previa que lo permita, decide la de bloqueo. | Bloqueado | Firewall |

### POL-11 · Microsegmentación por servicio y entorno

**Prioridad:** Crítica  
**Objetivo:** No hay movimiento lateral fuera de la matriz aprobada.  
**Requisitos de política:** Matriz de segmentación en la configuración.  
_Notas de Check Point: Se ejecuta la matriz completa desde cada entorno (en lote sobre todos los clientes)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-11.1 | Matriz completa de entornos | Matriz de segmentación configurada: desde este entorno hacia los demás se prueban ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 e iperf3, y se compara con lo permitido. | Según matriz | Firewall |

### POL-12 · Perfiles combinados

**Prioridad:** Alta  
**Objetivo:** Varios controles en el mismo flujo, cada uno con su traza.  
**Requisitos de política:** Perfil completo en la regla de salida y inspección TLS.  
_Notas de Check Point: En la salida a Internet se combinan Firewall, App Control, URL Filtering, IPS, Anti-Bot y Anti-Virus; el registro indica qué blade actuó._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-12.1 | EICAR desde Internet por HTTPS | Anti-Virus sobre HTTPS descifrado. | Bloqueado | Anti-malware / TLS inspection |
| POL-12.2 | Página de prueba de Anti-Bot | Reputación de C&C. | Bloqueado | Anti-bot (C&C) |
| POL-12.3 | Categoría Gambling | URL Filtering por categoría. | Bloqueado | URL Filtering |
| POL-12.4 | Sitio legítimo | Control: tráfico legítimo, no debe bloquearse. | Permitido | All |

### POL-15 · Modo detección frente a prevención

**Prioridad:** Alta  
**Objetivo:** El mismo estímulo solo se detecta en un destino y se bloquea en otro.  
**Requisitos de política:** Roles ids_target e ids_clients; regla TP con perfil Detect hacia ids_target; HTTP permitido desde ids_clients.  
_Notas de Check Point: Regla de Threat Prevention con perfil Detect hacia el entorno ids_target y perfil Prevent hacia el servidor._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-15.1 | SQLi hacia el destino en Detect (solo desde el papel `ids_clients`) | Llega al servidor y queda registrado como Detect. | Permitido | IPS |
| POL-15.2 | SQLi hacia el servidor en Prevent (solo desde el papel `ids_clients`) | Bloqueado y registrado como Prevent. | Bloqueado | IPS |

<a id="ips"></a>
## IPS · Prevención de intrusiones

### IPS-01 · Bloqueo de ataques conocidos

**Prioridad:** Crítica  
**Objetivo:** Las firmas detectan y bloquean; el registro incluye protección, severidad y acción.  
**Requisitos de política:** Perfil de prevención de amenazas con IPS en Prevent en la regla este-oeste.  
_Notas de Check Point: IPS en Prevent en todo el tráfico entre entornos y hacia Internet._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-01.1 | Petición limpia (control) | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |
| IPS-01.2 | SQL injection (UNION SELECT) | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.3 | Cross-site scripting | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.4 | Path traversal | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.5 | Path traversal en parámetro | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.6 | Shellshock (User-Agent) | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.7 | Log4Shell (cabecera JNDI) | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-01.8 | Inyección de comandos | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |

### IPS-02 · Escaneo y reconocimiento

**Prioridad:** Alta  
**Objetivo:** Un escaneo solo ve los servicios autorizados.  
**Requisitos de política:** Solo 80, 443 y el puerto de excepción permitidos hacia el servidor.  
_Notas de Check Point: El firewall descarta los puertos no autorizados aunque el servidor escuche; los intentos quedan registrados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-02.1 | Escaneo de puertos al servidor | nmap sobre 1-1024, 3389, 5201 y 8080: solo deben verse los autorizados. | Solo autorizados | Firewall / IPS |

### IPS-04 · Excepción de firma por activo

**Prioridad:** Crítica  
**Objetivo:** Solo queda exceptuada la combinación autorizada; el resto sigue protegido.  
**Requisitos de política:** Excepción en la regla este-oeste: protección «TP-Link Archer AX21 Command Injection (CVE-2023-1389)», origen = entorno ips_exception_client, acción Detect.  
_Notas de Check Point: Excepción de Threat Prevention con una sola protección (TP-Link Archer AX21, CVE-2023-1389), origen ips_exception_client y destino el servidor, en Detect._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-04.1 | CVE-2023-1389 desde el activo exceptuado (solo desde el papel `ips_exception_client`) | Dentro del alcance: Detect. | Permitido | IPS |
| IPS-04.2 | CVE-2023-1389 desde otro activo | Fuera del alcance: sigue bloqueado. | Bloqueado | IPS |
| IPS-04.3 | Otra protección desde el activo exceptuado (solo desde el papel `ips_exception_client`) | El resto de protecciones siguen activas. | Bloqueado | IPS |

### IPS-05 · Falsos positivos

**Prioridad:** Alta  
**Objetivo:** Tráfico legítimo parecido a firmas no se bloquea.  
**Requisitos de política:** Ninguno.  
_Notas de Check Point: Perfiles por confianza e impacto; el ajuste fino se hace con excepciones por activo, sin desactivar detecciones globalmente._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-05.1 | Texto con 'select' y 'union' | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |
| IPS-05.2 | Apellido con apóstrofo | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |
| IPS-05.3 | Filtro con comparadores | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |
| IPS-05.4 | JSON con HTML legítimo | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |
| IPS-05.5 | Script de shell legítimo | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS / Anti-malware |

### IPS-06 · Parcheo virtual de CVE publicadas

**Prioridad:** Alta  
**Objetivo:** Se bloquean patrones de explotación sin tocar el servidor.  
**Requisitos de política:** IPS en Prevent.  
_Notas de Check Point: El IPS bloquea la explotación de CVE conocidas; el servidor de pruebas no es vulnerable, solo recibe el patrón._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-06.1 | CVE-2021-41773 Apache path traversal | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.2 | CVE-2022-22965 Spring4Shell | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.3 | CVE-2022-26134 Confluence OGNL | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.4 | CVE-2017-9841 PHPUnit eval-stdin | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.5 | CVE-2019-19781 Citrix ADC traversal | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.6 | CVE-2022-1388 F5 BIG-IP iControl | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-06.7 | CVE-2021-44228 Log4Shell User-Agent | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |

### IPS-07 · Evasiones y fragmentación

**Prioridad:** Alta  
**Objetivo:** Las variantes ofuscadas y troceadas se detectan igual que el ataque original.  
**Requisitos de política:** IPS en Prevent.  
_Notas de Check Point: El IPS reensambla el flujo TCP y normaliza la codificación antes de buscar patrones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-07.1 | SQLi mayúsculas/minúsculas | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.2 | SQLi con comentarios en línea | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.3 | SQLi UNION en cuerpo POST | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.4 | Traversal con doble codificación | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.5 | XSS en cabecera Referer | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.6 | Log4Shell ofuscado | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| IPS-07.7 | SQLi troceada en segmentos TCP de 4 bytes | El IPS debe reensamblar el flujo antes de inspeccionar. | Bloqueado | IPS |
| IPS-07.8 | Control: petición limpia troceada | Control: tráfico legítimo, no debe bloquearse. | Permitido | IPS |

### IPS-08 · Geobloqueo

**Prioridad:** Alta  
**Objetivo:** Los destinos de países bloqueados se descartan.  
**Requisitos de política:** Regla de salida con los países bloqueados y una URL de prueba de uno de ellos (config.internet.geo_blocked_url).  
_Notas de Check Point: Objetos actualizables GEO en la capa de salida._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-08.1 | Destino en país bloqueado | IP de destino en un país bloqueado. | Bloqueado | Firewall (GEO) |
| IPS-08.2 | Destino en país permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall (GEO) |

### IPS-09 · C&C y botnets

**Prioridad:** Alta  
**Objetivo:** El tráfico hacia indicadores de C&C se bloquea.  
**Requisitos de política:** Anti-Bot en el perfil de salida.  
_Notas de Check Point: Anti-Bot bloquea por reputación de dominio, IP y URL (ThreatCloud) y por patrones de comunicación._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-09.1 | URL de prueba de C&C del fabricante | URL de prueba que el fabricante clasifica como C&C (configurable en Destinos en Internet). | Bloqueado | Anti-bot (C&C) |
| IPS-09.2 | Control: sitio corporativo permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-bot (C&C) |

### IPS-11 · Política diferenciada IDS frente a IPS

**Prioridad:** Alta  
**Objetivo:** El modo detección no bloquea; el de prevención sí; ambos registran.  
**Requisitos de política:** Igual que POL-15.  
_Notas de Check Point: Mismo estímulo contra el destino en Detect (ids_target) y contra el servidor en Prevent._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-11.1 | XSS hacia el destino IDS (solo desde el papel `ids_clients`) | Perfil Detect. | Permitido | IPS |
| IPS-11.2 | XSS hacia el servidor IPS (solo desde el papel `ids_clients`) | Perfil Prevent. | Bloqueado | IPS |
| IPS-11.3 | Log4Shell hacia el destino IDS (solo desde el papel `ids_clients`) | Perfil Detect. | Permitido | IPS |
| IPS-11.4 | Log4Shell hacia el servidor IPS (solo desde el papel `ids_clients`) | Perfil Prevent. | Bloqueado | IPS |

<a id="thr"></a>
## THR · Malware y amenazas

### THR-01 · Anti-malware sobre HTTP

**Prioridad:** Alta  
**Objetivo:** El fichero de prueba EICAR se detecta y bloquea.  
**Requisitos de política:** Anti-Virus con inspección en ambos sentidos y de archivos comprimidos.  
_Notas de Check Point: Anti-Virus (firmas + ThreatCloud) en HTTP/HTTPS, incluidos comprimidos anidados y subidas._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-01.1 | EICAR (.com) | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-01.2 | EICAR (.txt) | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-01.3 | EICAR en zip | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-01.4 | EICAR en zip dentro de zip | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-01.5 | EICAR subido en el cuerpo (POST) | Subida tipo API: el fichero va en el cuerpo de la petición. | Bloqueado | IPS / Anti-malware |
| THR-01.6 | Zip benigno (control) | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |

### THR-02 · Anti-malware en HTTPS con y sin descifrado

**Prioridad:** Alta  
**Objetivo:** Se cuantifica lo que aporta la inspección TLS.  
**Requisitos de política:** inspección TLS con bypass para nodecrypt.testkit.lab y mtls.testkit.lab.  
_Notas de Check Point: Mismo EICAR por HTTPS al mismo servidor con dos nombres: inspect.testkit.lab (descifrado) y nodecrypt.testkit.lab (excluido)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-02.1 | EICAR por HTTP | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-02.2 | EICAR por HTTPS descifrado | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| THR-02.3 | EICAR por HTTPS sin descifrar | Sin descifrado no hay visibilidad del contenido (resultado esperado). | Permitido | TLS inspection (bypass) |
| THR-02.4 | EICAR desde Internet por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |

### THR-03 · Ficheros benignos sin falsos positivos

**Prioridad:** Alta  
**Objetivo:** Ficheros limpios de varios formatos y tamaños no se bloquean.  
**Requisitos de política:** Ninguno.  
_Notas de Check Point: Descargas por HTTP y HTTPS._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-03.1 | benign.pdf por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.2 | benign.pdf por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.3 | benign.docx por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.4 | benign.docx por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.5 | benign.xlsx por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.6 | benign.xlsx por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.7 | benign.png por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.8 | benign.png por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.9 | benign.json por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.10 | benign.json por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.11 | benign.csv por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.12 | benign.csv por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.13 | benign_10m.bin por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |
| THR-03.14 | benign_10m.bin por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-malware |

### THR-05 · AV, Anti-Bot e IPS combinados

**Prioridad:** Alta  
**Objetivo:** Los controles combinados no se anulan y muestran quién actuó.  
**Requisitos de política:** Perfil completo y inspección TLS.  
_Notas de Check Point: Varios blades en el mismo perfil._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-05.1 | EICAR en zip por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| THR-05.2 | SQLi por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| THR-05.3 | C&C por HTTP | Anti-Bot. | Bloqueado | Anti-bot (C&C) |

<a id="tls"></a>
## TLS · Inspección y cifrado TLS

### TLS-01 · Inspección TLS 1.2 y 1.3

**Prioridad:** Crítica  
**Objetivo:** Se documenta qué versiones se inspeccionan y se bloquean patrones dentro de ellas.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTPS Inspection inspecciona TLS 1.2 y 1.3 re-firmando con la CA de inspección._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-01.1 | TLS 1.2 descifrado | El certificado recibido lo emite la CA de inspección. | Descifrado | TLS inspection |
| TLS-01.2 | TLS 1.3 descifrado | Igual con TLS 1.3. | Descifrado | TLS inspection |
| TLS-01.3 | SQLi sobre TLS 1.2 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-01.4 | SQLi sobre TLS 1.3 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-01.5 | Petición limpia sobre TLS 1.3 | Control: tráfico legítimo, no debe bloquearse. | Permitido | TLS inspection |

### TLS-02 · CA de inspección y cadena de confianza

**Prioridad:** Alta  
**Objetivo:** Solo los clientes que confían en la CA funcionan; no hay bypass encubierto.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: La CA de inspección se distribuye a los clientes; un cliente sin ella recibe un error de certificado._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-02.1 | Certificado sustituido en Internet | La web llega firmada por la CA de inspección. | Descifrado | TLS inspection |
| TLS-02.2 | Cliente con la CA de inspección | Valida con la CA de inspección en su almacén. | Cert. válido | TLS inspection |
| TLS-02.3 | Cliente sin la CA de inspección | Solo CA públicas: falla. | Cert. rechazado | TLS inspection |

### TLS-03 · Certificados caducados, revocados o no confiables

**Prioridad:** Alta  
**Objetivo:** La respuesta coincide con la política de validación y queda registrada.  
**Requisitos de política:** HTTPS advanced settings: bloquear no confiables, caducados y revocados.  
_Notas de Check Point: HTTPS Inspection valida el certificado original y bloquea los no confiables, caducados y revocados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-03.1 | Certificado caducado | Validación del certificado del servidor. | Bloqueado | TLS inspection |
| TLS-03.2 | Certificado autofirmado | CA no confiable. | Bloqueado | TLS inspection |
| TLS-03.3 | Raíz no confiable | Cadena hasta una raíz desconocida. | Bloqueado | TLS inspection |
| TLS-03.4 | Certificado revocado | Revocado. | Bloqueado | TLS inspection |
| TLS-03.5 | Control: certificado válido | Control: tráfico legítimo, no debe bloquearse. | Permitido | TLS inspection |

### TLS-04 · mTLS y certificate pinning

**Prioridad:** Alta  
**Objetivo:** Las incompatibilidades se resuelven con una exclusión mínima.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: mTLS y pinning no admiten intermediario: se excluyen del descifrado solo esos FQDN._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-04.1 | mTLS con certificado de cliente (excluido) | El servidor exige certificado de cliente. | Permitido | TLS inspection (bypass) |
| TLS-04.2 | Pinning de CA (excluido) | Cliente que solo confía en la CA del servicio. | Cert. válido | TLS inspection (bypass) |
| TLS-04.3 | Pinning de CA (inspeccionado) | Contra el FQDN inspeccionado falla: el pinning requiere exclusión. | Cert. rechazado | TLS inspection |

### TLS-05 · Exclusiones de descifrado por FQDN y categoría

**Prioridad:** Crítica  
**Objetivo:** Solo el alcance aprobado queda sin descifrar.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Exclusiones por FQDN, por categorías sensibles (finanzas, salud, gobierno) y por la lista recomendada de Check Point._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-05.1 | FQDN excluido | No se descifra. | Sin descifrar | TLS inspection |
| TLS-05.2 | FQDN inspeccionado | Se descifra. | Descifrado | TLS inspection |
| TLS-05.3 | Banca (categoría Financial) | Categoría sensible excluida. | Sin descifrar | TLS inspection |
| TLS-05.4 | Web general | Se descifra. | Descifrado | TLS inspection |

### TLS-06 · HTTP/2, QUIC y ECH

**Prioridad:** Alta  
**Objetivo:** Se conoce la visibilidad efectiva y no hay bypass silencioso.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTP/2 se inspecciona igual que HTTP/1.1; QUIC (UDP/443) se deniega para forzar TCP inspeccionado._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-06.1 | SQLi por HTTP/2 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-06.2 | EICAR por HTTP/2 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| TLS-06.3 | Petición limpia por HTTP/2 | Control: tráfico legítimo, no debe bloquearse. | Permitido | TLS inspection |
| TLS-06.4 | QUIC (UDP/443) a Internet | Paquete QUIC Initial: sin respuesta. | Bloqueado | Firewall |

### TLS-07 · Modo transparente y observabilidad

**Prioridad:** Media  
**Objetivo:** Se conoce el impacto sobre la IP de origen.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Detrás de GWLB el firewall es transparente: conserva la IP original y no añade cabeceras de proxy._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-07.1 | IP de origen conservada (HTTPS inspeccionado) | El servidor devuelve la IP y cabeceras que ve. | IP conservada | TLS inspection |

### TLS-08 · Sobrecoste de la inspección TLS

**Prioridad:** Crítica  
**Objetivo:** Se obtiene el sobrecoste real de handshake y latencia.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: 100 conexiones HTTPS nuevas con y sin descifrado al mismo servidor; se comparan percentiles._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-08.1 | Sobrecoste de inspección TLS | inspect.testkit.lab frente a nodecrypt.testkit.lab. | Medida | TLS inspection |

### TLS-09 · Amenazas dentro de HTTPS (este-oeste)

**Prioridad:** Alta  
**Objetivo:** Las cargas de IPS y AV dentro de HTTPS se bloquean igual que en HTTP.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTPS Inspection este-oeste devuelve la visibilidad a IPS, AV y DLP._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-09.1 | XSS por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-09.2 | Path traversal por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-09.3 | Log4Shell por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-09.4 | Shellshock por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-09.5 | EICAR por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| TLS-09.6 | Petición limpia por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | TLS inspection |

### TLS-10 · Evasión y ofuscación sobre HTTPS

**Prioridad:** Alta  
**Objetivo:** Ninguna técnica permite eludir los controles.  
**Requisitos de política:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Con HTTPS Inspection el gateway ve el Host real, descomprime gzip, reensambla chunked/multipart y valida el protocolo por puerto._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-10.1 | Domain fronting (SNI permitido, Host bloqueado) | Con descifrado se ve el Host real. | Bloqueado | Application control / TLS inspection |
| TLS-10.2 | EICAR con Content-Encoding gzip | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| TLS-10.3 | EICAR subido por multipart (HTTPS) | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| TLS-10.4 | SQLi en cuerpo chunked (HTTP/1.1 sobre TLS) | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-10.5 | HTTPS a puerto no estándar (8443) | TLS fuera de 443. | Bloqueado | Firewall |
| TLS-10.6 | Datos de tarjeta en JSON por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | DLP / TLS inspection |

<a id="app"></a>
## APP · Control L7 y anomalías

### APP-01 · Control de aplicaciones independiente del puerto

**Prioridad:** Alta  
**Objetivo:** La aplicación se identifica por protocolo y no por puerto.  
**Requisitos de política:** Servicios HTTP/HTTPS con identificación por protocolo (no solo por puerto) y SSH bloqueado como aplicación.  
_Notas de Check Point: App Control identifica aplicaciones en cualquier puerto y la salida solo admite HTTP/HTTPS con firma de protocolo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-01.1 | SSH tcp/22 a Internet | Puerto y aplicación no permitidos. | Bloqueado | Firewall |
| APP-01.2 | SSH por tcp/443 | SSH sobre el puerto de HTTPS (ssh.github.com). | Bloqueado | Application control |
| APP-01.3 | HTTP en tcp/8080 | Puerto no autorizado. | Bloqueado | Firewall |
| APP-01.4 | HTTP en tcp/8443 | Puerto no autorizado. | Bloqueado | Firewall |
| APP-01.5 | HTTP en claro por tcp/443 | No es TLS: no coincide con el servicio HTTPS con firma. | Bloqueado | Firewall |
| APP-01.6 | Control: HTTP en tcp/80 | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall |

### APP-02 · URL Filtering y App Control por categorías

**Prioridad:** Alta  
**Objetivo:** Categoría y acción quedan registradas.  
**Requisitos de política:** Categorías Gambling y Anonymizer, y aplicaciones Facebook, TikTok, Dropbox y WeTransfer bloqueadas; LinkedIn permitida.  
_Notas de Check Point: URL Filtering por categorías y App Control por aplicación, en HTTP y HTTPS._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-02.1 | Sitio corporativo (permitido) | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering |
| APP-02.2 | bet365 (Gambling) por HTTP | Categoría prohibida. | Bloqueado | URL Filtering |
| APP-02.3 | pokerstars (Gambling) por HTTPS | Categoría prohibida. | Bloqueado | URL Filtering / TLS inspection |
| APP-02.4 | hidemyass (Anonymizer) | Anonimizador. | Bloqueado | URL Filtering |
| APP-02.5 | Facebook | Aplicación bloqueada. | Bloqueado | Application control |
| APP-02.6 | TikTok | Aplicación bloqueada. | Bloqueado | Application control |
| APP-02.7 | Dropbox | Compartición de ficheros. | Bloqueado | Application control |
| APP-02.8 | WeTransfer | Compartición de ficheros. | Bloqueado | Application control |
| APP-02.9 | LinkedIn (permitida) | Control: tráfico legítimo, no debe bloquearse. | Permitido | Application control |

### APP-03 · URL completa frente a dominio/SNI

**Prioridad:** Alta  
**Objetivo:** Se demuestra cuándo se distingue la ruta del dominio.  
**Requisitos de política:** Sitio personalizado con la ruta bloqueada configurada (config.internet.blocked_path).  
_Notas de Check Point: Con HTTPS Inspection se ve la URL completa y se puede bloquear una ruta; sin descifrado solo el dominio._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-03.1 | Ruta permitida por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering |
| APP-03.2 | Ruta bloqueada por HTTP | Coincide la ruta. | Bloqueado | URL Filtering |
| APP-03.3 | Ruta permitida por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering / TLS inspection |
| APP-03.4 | Ruta bloqueada por HTTPS | Solo posible con descifrado. | Bloqueado | URL Filtering / TLS inspection |

### APP-04 · Filtrado independiente del DNS

**Prioridad:** Alta  
**Objetivo:** Se conoce la superficie cubierta: IP directa, sin SNI, DoH y DoT.  
**Requisitos de política:** Aplicación DoH bloqueada; solo DNS/HTTP/HTTPS en la salida.  
_Notas de Check Point: Identificación por Host, SNI y certificado; DoH bloqueado como aplicación y DoT por puerto._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-04.1 | Facebook por IP con cabecera Host | Sin consulta DNS. | Bloqueado | Application control |
| APP-04.2 | Facebook por IP sin SNI (HTTPS) | Se clasifica por el certificado. | Bloqueado | Application control / TLS inspection |
| APP-04.3 | DNS sobre HTTPS | Aplicación DoH. | Bloqueado | Application control |
| APP-04.4 | DNS sobre TLS (tcp/853) | DoT por su puerto estándar. | Bloqueado | Firewall |

### APP-07 · Conexiones salientes inesperadas

**Prioridad:** Alta  
**Objetivo:** Un servidor no puede abrir conexiones a destinos y puertos no previstos.  
**Requisitos de política:** Capa de salida con cleanup en Drop.  
_Notas de Check Point: Salida denegada por defecto; cada intento queda registrado._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-07.1 | SQL Server tcp/1433 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.2 | MySQL tcp/3306 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.3 | PostgreSQL tcp/5432 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.4 | SMTP tcp/25 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.5 | SMB tcp/445 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |

<a id="dlp"></a>
## DLP · Prevención de fuga de datos

### DLP-01 · Transferencia de datos sensibles

**Prioridad:** Media  
**Objetivo:** Se detectan y bloquean patrones sensibles sintéticos.  
**Requisitos de política:** Reglas de DLP (inspección de contenido) (PCI, IBAN, ejecutables) entre entornos sobre HTTP y HTTPS.  
_Notas de Check Point: Content Awareness con tipos de datos PCI e IBAN y tipo de fichero ejecutable._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| DLP-01.1 | Subida de fichero benigno | Control: tráfico legítimo, no debe bloquearse. | Permitido | DLP |
| DLP-01.2 | Subida de tarjetas (PCI) | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP |
| DLP-01.3 | Subida de IBAN | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP |
| DLP-01.4 | Descarga de tarjetas (PCI) | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP |
| DLP-01.5 | Descarga de ejecutable | Tipo de fichero ejecutable. | Bloqueado | DLP |

### DLP-02 · Excepciones DLP de alcance mínimo

**Prioridad:** Media  
**Objetivo:** La excepción se aplica solo al activo y sentido aprobados.  
**Requisitos de política:** Rol dlp_exception_client y regla de excepción con dirección 'up'.  
_Notas de Check Point: Regla de excepción (solo subida desde dlp_exception_client al servidor) por encima de la de bloqueo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| DLP-02.1 | Subida PCI desde el activo exceptuado (solo desde el papel `dlp_exception_client`) | Dentro del alcance. | Permitido | DLP |
| DLP-02.2 | Subida PCI desde otro activo | Mismo fichero y destino desde otro activo. | Bloqueado | DLP |
| DLP-02.3 | Descarga PCI hacia el activo exceptuado (solo desde el papel `dlp_exception_client`) | La excepción solo cubre la subida. | Bloqueado | DLP |

### DLP-03 · DLP sobre tráfico cifrado y distintos tamaños

**Prioridad:** Media  
**Objetivo:** Se documentan los límites por formato, cifrado y tamaño.  
**Requisitos de política:** Reglas de DLP (inspección de contenido) (PCI, IBAN, ejecutables) entre entornos sobre HTTP y HTTPS.  
_Notas de Check Point: Content Awareness sobre HTTPS descifrado, ficheros grandes y Office._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| DLP-03.1 | Subida PCI por HTTPS | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP / TLS inspection |
| DLP-03.2 | Descarga PCI por HTTPS | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP / TLS inspection |
| DLP-03.3 | PCI al final de un fichero de 2 MB | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP |
| DLP-03.4 | PCI dentro de un .docx | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP |
| DLP-03.5 | Ejecutable por HTTPS | DLP (inspección de contenido) inspecciona el contenido transferido (subida y descarga) y bloquea datos sensibles sintéticos. | Bloqueado | DLP / TLS inspection |

<a id="waf"></a>
## WAF · Protección web complementaria

### WAF-01 · SQLi y XSS (cobertura de WAF)

**Prioridad:** Media  
**Objetivo:** Se documenta qué cubre el IPS y qué requiere un WAF.  
**Requisitos de política:** IPS en Prevent.  
_Notas de Check Point: El IPS cubre las clases comunes de ataque web. La protección completa de aplicaciones y API (incluidas tautologías en formularios y JSON) corresponde a Check Point CloudGuard WAF._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| WAF-01.1 | SQLi en parámetro GET | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| WAF-01.2 | XSS reflejado | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| WAF-01.3 | Tautología SQL en formulario POST (informativa) | Clase propia de un WAF: informativa. | Bloqueado | IPS → WAF |
| WAF-01.4 | Tautología SQL en JSON (API) (informativa) | Clase propia de un WAF: informativa. | Bloqueado | IPS → WAF |
