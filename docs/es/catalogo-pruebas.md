# Catálogo de pruebas

_English: [test-catalog.md](../en/test-catalog.md)_

Generado desde `catalog/tests.json`. Cada caso indica su objetivo, los requisitos de política, las comprobaciones automáticas y, aparte, notas de cómo lo resuelve Check Point (en el portal y los informes solo aparecen si la solución probada es Check Point).

## Resumen

| Dominio | Casos | Manuales | Comprobaciones |
|---|---:|---:|---:|
| [NET · Arquitectura y enrutamiento](#net) | 13 | 7 | 17 |
| [POL · Políticas y segmentación](#pol) | 16 | 6 | 22 |
| [IPS · Prevención de intrusiones](#ips) | 11 | 0 | 42 |
| [THR · Malware y amenazas](#thr) | 6 | 1 | 28 |
| [TLS · Inspección y cifrado TLS](#tls) | 10 | 0 | 38 |
| [APP · Control L7 y anomalías](#app) | 8 | 3 | 28 |
| [DLP · Prevención de fuga de datos](#dlp) | 3 | 0 | 13 |
| [WAF · Protección web complementaria](#waf) | 3 | 2 | 4 |
| [OBS · Visibilidad y auditoría](#obs) | 11 | 8 | 4 |
| [HA · Disponibilidad y resiliencia](#ha) | 8 | 3 | 5 |
| [PERF · Rendimiento y capacidad](#perf) | 8 | 0 | 19 |
| [OPS · Operación y gobierno](#ops) | 9 | 7 | 2 |
| [INT · Integraciones](#int) | 6 | 6 | 0 |
| [COST · Coste y eficiencia](#cost) | 5 | 5 | 0 |

## Configuración del firewall para las pruebas

1. Arquitectura: todo el tráfico entre entornos y hacia Internet pasa por el firewall (Transit Gateway con appliance mode en el attachment de inspección y endpoints del balanceador del firewall). Sin rutas alternativas (NET-06).
2. Objetos: un objeto de red por entorno (CIDR de la configuración del portal) y un grupo con todos ellos; un objeto con el rango interno.
3. Segmentación: una regla Accept por cada par origen→destino de la matriz con sus servicios, una regla Drop con registro para el resto entre entornos y regla de limpieza Drop con registro.
4. Puerto de excepción (por defecto 5201, TCP y UDP): permitido entre todos los entornos y excluido de la prevención de amenazas (POL-02 y medidas de rendimiento PERF-01/06/07).
5. Salida a Internet: solo HTTP/HTTPS identificados por protocolo y DNS; control de aplicaciones y URL (categorías de riesgo, FQDN y ruta bloqueados de la configuración), geobloqueo de los países configurados y anti-bot.
6. Prevención de amenazas en Prevent: IPS, anti-malware (ambos sentidos y dentro de comprimidos) y anti-bot; un perfil este-oeste, uno de Internet y uno en Detect para el entorno «ids_target»; una excepción IPS para el activo «ips_exception_client».
7. DLP: bloqueo de tarjetas, IBAN y ejecutables entre entornos (HTTP y HTTPS), con una excepción de subida para el activo «dlp_exception_client».
8. Inspección TLS: descifrado saliente y este-oeste con la CA de inspección (su PEM se carga en el portal); la CA del kit como CA de confianza; exclusión de descifrado para el FQDN mTLS/pinning, la lista del fabricante y categorías sensibles (financiero, salud, gobierno); validación del certificado del servidor.
9. Registro: todas las reglas con registro (las de amenazas con captura de paquetes); hora sincronizada por NTP.
10. Agente de control: clave de API de gestión (lectura, publicar e instalar solo en los gateways de prueba; crea objetos temporales TK_ que elimina) y rol de nube para leer el despliegue y ejecutar las pruebas de HA (grupo de autoescalado, ACL de red, CloudWatch, IAM de lectura).

### Configuración base recomendada de Check Point

- Perfil de amenazas basado en «Optimized» (o «Strict» en la salida a Internet) en Prevent, con IPS, Anti-Bot, Anti-Virus, Threat Emulation y Threat Extraction; las protecciones nuevas en Prevent según confianza y rendimiento.
- Autonomous Threat Prevention o actualizaciones automáticas de IPS y de ThreatCloud; revisar THR-06 tras cada alta de gateway.
- Inspección HTTPS saliente con la CA corporativa distribuida por GPO/MDM, bypass del objeto actualizable «HTTPS services - recommended bypass» (sk163595) y de categorías sensibles; validación del certificado del servidor y bloqueo de certificados no válidos.
- Capas ordenadas en secciones (excepciones, matriz, salida, limpieza), sin reglas Accept con «Any» en servicio o destino, regla de limpieza Drop con registro y objetos dinámicos/actualizables en lugar de IP fijas.
- Servicios con «match by protocol signature» para HTTP/HTTPS en la salida (bloquea túneles en puertos web).
- Geo Policy / objetos actualizables de países en la salida y en el ingress publicado.
- Alta disponibilidad: grupo de autoescalado en al menos 2 AZ con mínimo n+1, GWLB con cross-zone activado, appliance mode en el TGW y CME con plantilla y política asignadas.
- Rendimiento: instancias de la familia c5/c6i/c7i dimensionadas con PERF-02 (perfil real), SecureXL y CoreXL activos (por defecto) y Dynamic Balancing.
- Gestión: Smart-1 Cloud con SSO+MFA, una clave API por automatización, sesiones con aprobación para cambios y política como código (Terraform/API).
- Bastionado de gateways: IMDSv2, volúmenes cifrados, acceso administrativo solo desde la gestión y rangos autorizados, y conector de nube con rol STS de solo lectura con ExternalId.
- Registros: Log Exporter hacia el SIEM, retención según normativa y Infinity Events/SmartEvent para correlación.

<a id="net"></a>
## NET · Arquitectura y enrutamiento

### NET-01 · Inspección este-oeste entre VPC

**Prioridad:** Crítica  
**Objetivo:** Los flujos entre entornos atraviesan el firewall en ambos sentidos y se permiten o deniegan según la matriz.  
**Configuración necesaria en el firewall:** Regla que permite ICMP, HTTP y HTTPS hacia el entorno del servidor y deniega el resto.  
_Notas de Check Point: El tráfico entre VPC pasa por el Transit Gateway hacia la VPC de inspección (GWLBe) y el Gateway Load Balancer lo entrega a Check Point Cloud Firewall. Cada decisión queda registrada con la regla que la tomó._  
_Buena práctica de Check Point: Una regla por par de entornos y servicio; sin «Any» como servicio._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-01.1 | ICMP echo al servidor | Ping desde la IP de workload. | Permitido | Firewall |
| NET-01.2 | HTTP tcp/80 al servidor | Servicio publicado. | Permitido | Firewall |
| NET-01.3 | HTTPS tcp/443 al servidor | Servicio publicado e inspeccionado. | Permitido | Firewall |
| NET-01.4 | SSH tcp/22 al servidor | El servidor escucha, pero la política no lo permite. | Bloqueado | Firewall |
| NET-01.5 | Telnet tcp/23 al servidor | Protocolo inseguro con servicio a la escucha. | Bloqueado | Firewall |
| NET-01.6 | tcp/8080 al servidor | HTTP alternativo no autorizado. | Bloqueado | Firewall |
| NET-01.7 | RDP tcp/3389 al servidor | Administración remota no autorizada. | Bloqueado | Firewall |

### NET-02 · Aislamiento y control intra-VPC

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Se identifica qué tráfico dentro de una misma VPC pasa por el firewall y cuál queda fuera.  
**Configuración necesaria en el firewall:** Dos instancias en subredes distintas de la misma VPC.  
_Notas de Check Point: Con GWLB se pueden insertar endpoints entre subredes de la misma VPC mediante rutas más específicas que la local (AWS lo permite desde 2021)._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Despliega dos instancias en subredes distintas de la misma VPC.
2. Genera tráfico entre ellas (ICMP, tcp/22, tcp/443) y busca esas conexiones en los registros del firewall.
3. Si no aparecen, el tráfico se resuelve por la ruta local de la VPC: documenta el control con security groups/NACL.
4. Si se necesita inspección intra-VPC, añade rutas más específicas (VPC route ingress / subred a subred) hacia el endpoint del firewall y repite.

**Resultado esperado:** Inventario explícito de flujos intra-VPC inspeccionados y no inspeccionados; ninguna cobertura supuesta.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-03 · Salida norte-sur a Internet

**Prioridad:** Crítica  
**Objetivo:** La salida a Internet se inspecciona de forma centralizada; solo pasa lo previsto.  
**Configuración necesaria en el firewall:** Capa de salida que permite solo HTTP, HTTPS y DNS.  
_Notas de Check Point: Salida centralizada (spoke → TGW → inspección → VPC de salida con NAT Gateway). En el firewall, una capa en línea permite HTTP/HTTPS (con firma de protocolo) y DNS, y deniega el resto._  
_Buena práctica de Check Point: NAT centralizado en la VPC de salida; el firewall ve la IP real del workload._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-03.1 | HTTP a Internet | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall |
| NET-03.2 | HTTPS a Internet | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall / TLS inspection |
| NET-03.3 | DNS UDP a resolvedor público | Consulta DNS directa: servicio permitido. | Permitido | Firewall |
| NET-03.4 | SMTP tcp/25 a Internet | Puerto no web hacia Internet. | Bloqueado | Firewall |
| NET-03.5 | NTP UDP/123 a Internet | UDP distinto de DNS no está permitido. | Bloqueado | Firewall |
| NET-03.6 | IP pública de salida | Muestra la IP pública con la que se sale (NAT centralizado). | Permitido | Architecture |

### NET-04 · Ingress norte-sur hacia servicios publicados

**Prioridad:** Alta · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** El tráfico entrante desde Internet a servicios publicados se inspecciona.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita un servicio publicado (ALB/NLB) con la ruta de entrada por el firewall.  
_Notas de Check Point: Check Point recomienda ingress con GWLB (preserva la IP de origen) y, para aplicaciones web y API, CloudGuard WAF delante del servicio._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Publica un servicio de prueba detrás de un balanceador en una VPC de ingress.
2. Enruta la entrada (IGW edge association o VPC de ingress) a través de los endpoints del firewall.
3. Desde Internet lanza peticiones legítimas y ataques (SQLi, XSS, escaneo) y verifica bloqueo y registros con la IP real del cliente.

**Resultado esperado:** Ataques bloqueados, tráfico legítimo permitido y registros con la IP de origen real.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-05 · Simetría de enrutamiento stateful entre AZ

**Prioridad:** Crítica  
**Objetivo:** Ida y vuelta de un flujo entre AZ distintas llegan al mismo contexto stateful.  
**Configuración necesaria en el firewall:** Pares de entornos en AZ distintas (configuración) con HTTP permitido entre ellos.  
_Notas de Check Point: Con el attachment de inspección en appliance mode, ambos sentidos usan el mismo GWLBe y el GWLB los entrega al mismo gateway; la sesión no se rompe._  
_Buena práctica de Check Point: Appliance mode en el attachment de inspección (obligatorio para simetría entre AZ)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-05.1 | Sesión TCP de 20 s con el par de otra AZ | Conexión HTTP persistente con 10 peticiones en 20 s: con asimetría, el firewall descartaría la vuelta. | Permitido | Architecture |

### NET-06 · Caminos alternativos y bypass

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Ningún camino de red permite que el tráfico de los workloads evite el firewall.  
**Configuración necesaria en el firewall:** Agente de control en marcha con credenciales de la nube (lectura; las pruebas de HA cambian el grupo de autoescalado y las ACL de red) y de la API de gestión.  
_Notas de Check Point: Se auditan las tablas de rutas de las subredes de workload (sin IGW, NAT, peering, VGW ni endpoints de gateway), la tabla del Transit Gateway de los spokes (todo hacia el attachment de inspección con appliance mode) y los peerings._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-06.1 | Auditoría de rutas de workload y del TGW | Lee las rutas reales de la cuenta: cualquier ruta que salte la inspección es un fallo. | Cumple criterio | Architecture |

### NET-07 · Segmentación entre producción y no producción

**Prioridad:** Crítica  
**Objetivo:** No hay tráfico entre producción y no producción salvo las excepciones aprobadas.  
**Configuración necesaria en el firewall:** Roles prod_envs y nonprod_envs y la matriz de segmentación.  
_Notas de Check Point: Los entornos se definen por CIDR y reglas explícitas bloquean producción ↔ no producción en ambos sentidos._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-07.1 | Matriz producción ↔ no producción | Matriz de segmentación configurada: desde este entorno hacia los demás se prueban ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 e iperf3, y se compara con lo permitido. | Según matriz | Firewall |

### NET-08 · Ruteo selectivo / service chaining

**Prioridad:** Alta · _Manual_  
**Objetivo:** Solo el tráfico elegido se envía a inspección y el resto sigue su camino sin romperse.  
**Configuración necesaria en el firewall:** Tablas de rutas del Transit Gateway editables.  
_Notas de Check Point: Preferible excluir por política (regla de acceso + excepción de amenazas) antes que por rutas: mantiene registro y visibilidad._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Define qué destinos deben pasar por inspección y cuáles no (p. ej. tráfico a un servicio interno de confianza).
2. Ajusta rutas del TGW/VPC para excluir solo ese destino y comprueba con los registros que el resto sigue inspeccionado.
3. Verifica simetría: ambos sentidos del flujo excluido evitan el firewall (si no, se rompe la sesión).

**Resultado esperado:** La exclusión afecta solo al destino definido, es simétrica y queda documentada.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-09 · Cambio de topología o rutas sin degradar seguridad

**Prioridad:** Alta · _Manual_  
**Objetivo:** Un cambio de rutas o de VPC no abre caminos sin inspección.  
**Configuración necesaria en el firewall:** Entorno de pruebas donde se puedan añadir VPC y rutas.  
_Notas de Check Point: Usar objetos de datacenter (CloudGuard Controller) o etiquetas para que los spokes nuevos hereden la política._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Añade un spoke nuevo o cambia una ruta del TGW (como en una operación real).
2. Ejecuta NET-06 (auditoría de rutas) y la matriz de segmentación (NET-01/NET-07) antes y después.
3. Comprueba que la política agrupa el nuevo spoke por objeto dinámico/etiqueta sin editar reglas.

**Resultado esperado:** Sin rutas de bypass y misma matriz de resultados tras el cambio.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-10 · Egress y routing IPv6

**Prioridad:** Alta · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** El tráfico IPv6 se inspecciona igual que el IPv4.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita VPC con IPv6 y egress-only IGW enrutado por el firewall.  
_Notas de Check Point: Confirmar el soporte IPv6 de la versión y del modo GWLB desplegados y crear las reglas con objetos IPv6._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Activa IPv6 en un spoke y en la VPC de inspección.
2. Enruta ::/0 hacia el endpoint del firewall y sal a Internet por IPv6.
3. Repite las pruebas de NET-03 y APP-02 por IPv6 y compara los registros.

**Resultado esperado:** Mismas decisiones y registros en IPv4 e IPv6.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-11 · Conectividad híbrida AWS–on-prem

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** El tráfico entre la nube y el centro de datos pasa por inspección.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita VPN o Direct Connect al TGW.  
_Notas de Check Point: Mismo diseño de tablas del TGW que para los spokes; appliance mode en el attachment de inspección._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Conecta una VPN/Direct Connect al TGW y asocia su attachment a la tabla que envía a inspección.
2. Genera tráfico on-prem ↔ spokes y comprueba en los registros que se inspecciona en ambos sentidos.

**Resultado esperado:** Tráfico híbrido inspeccionado y simétrico.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-12 · Conectividad intercloud AWS–Azure

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** El tráfico entre nubes se inspecciona con la misma política.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita un entorno Azure conectado (VPN/ExpressRoute).  
_Notas de Check Point: Una única gestión (Smart-1 Cloud) para gateways de AWS y Azure: mismos objetos, capas y registros._  
_Buena práctica de Check Point: GWLB con appliance mode en el attachment de inspección del TGW y cross-zone activado; MTU de las instancias compatible con GENEVE (8500 en la VPC del firewall)._

**Procedimiento:**

1. Conecta AWS y Azure (VPN entre TGW y Virtual WAN/VNet).
2. Despliega un cliente del kit en Azure y ejecuta la matriz de segmentación entre nubes.
3. Compara la política y los registros en ambas nubes desde la misma consola.

**Resultado esperado:** Misma política y visibilidad unificada en ambas nubes.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### NET-13 · MTU, fragmentación y GENEVE

**Prioridad:** Alta  
**Objetivo:** No hay agujeros negros por MTU; el tamaño máximo útil queda medido.  
**Configuración necesaria en el firewall:** ICMP permitido hacia el servidor.  
_Notas de Check Point: GWLB encapsula en GENEVE y admite MTU de 8.500 bytes. Se mide el mayor paquete que pasa sin fragmentar._  
_Buena práctica de Check Point: Jumbo frames en la VPC del firewall; MSS clamping si hay saltos con MTU 1500._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| NET-13.1 | MTU efectiva hacia el servidor | Ping con DF de 1.472 a 8.472 bytes. Criterio: ≥ 1.472. | Medida | Architecture |

<a id="pol"></a>
## POL · Políticas y segmentación

### POL-01 · Allow/deny stateful y denegación por defecto

**Prioridad:** Crítica  
**Objetivo:** Solo pasan las 5-tuplas autorizadas; el resto se descarta y se registra.  
**Configuración necesaria en el firewall:** Lista blanca hacia el servidor y cleanup.  
_Notas de Check Point: Política stateful con lista blanca y regla de limpieza final (Drop + Log)._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-01.1 | tcp/80 autorizado | 5-tupla autorizada. | Permitido | Firewall |
| POL-01.2 | tcp/443 autorizado | 5-tupla autorizada. | Permitido | Firewall |
| POL-01.3 | tcp/22 no autorizado | Mismo origen y destino, puerto no autorizado. | Bloqueado | Firewall |
| POL-01.4 | tcp/5202 no autorizado | Puerto contiguo a una excepción. | Bloqueado | Firewall |

### POL-02 · Excepciones granulares por 5-tupla

**Prioridad:** Crítica  
**Objetivo:** Una excepción solo abre el flujo indicado; puertos vecinos siguen bloqueados.  
**Configuración necesaria en el firewall:** Regla que permita solo el puerto de excepción configurado.  
_Notas de Check Point: Regla de excepción para un único puerto (por defecto iperf3 tcp/5201) entre entornos._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-02.1 | Puerto exceptuado | Flujo exceptuado. | Permitido | Firewall |
| POL-02.2 | Puerto vecino inferior | No debe quedar abierto. | Bloqueado | Firewall |
| POL-02.3 | Puerto vecino superior | No debe quedar abierto. | Bloqueado | Firewall |

### POL-03 · Granularidad por aplicación, identidad o etiqueta

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Las reglas pueden usar aplicación, identidad y etiquetas de la nube, no solo IP/puerto.  
**Configuración necesaria en el firewall:** Conector de nube (lectura de etiquetas) y, para identidad, un proveedor de identidad.  
_Notas de Check Point: CloudGuard Controller (objetos de datacenter de AWS por etiqueta) e Identity Awareness; las reglas usan objetos, nunca IP fijas de workloads._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Crea una regla que use una aplicación (p. ej. bloquear una aplicación concreta) y verifica su efecto con el kit (APP-01).
2. Crea un objeto dinámico por etiqueta de instancia y úsalo como origen de una regla; cambia la etiqueta de una instancia y comprueba que la regla la sigue.
3. Si aplica, crea una regla por grupo de identidad y verifica el registro con el usuario.

**Resultado esperado:** Reglas por aplicación, etiqueta e identidad efectivas y registradas.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-04 · Caducidad, aprobación y reversión de excepciones

**Prioridad:** Alta · _Manual_  
**Objetivo:** Las excepciones tienen dueño, aprobación y fecha de caducidad, y se pueden revertir.  
**Configuración necesaria en el firewall:** Flujo de cambios con aprobación (sesiones con aprobación o ITSM).  
_Notas de Check Point: Campo «Time» de la regla (objeto de tiempo con fecha de fin), Session approval workflow y revisiones de política (Installation History)._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Crea una regla de excepción con fecha de caducidad y comentario con el número de cambio.
2. Publica con aprobación de un segundo administrador.
3. Verifica que la regla deja de aplicar al caducar y revierte la publicación a la revisión anterior.

**Resultado esperado:** Excepción aprobada, caducada automáticamente y revertible con trazabilidad.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-05 · Reglas por FQDN

**Prioridad:** Crítica  
**Objetivo:** La decisión se toma por el dominio, no por la IP.  
**Configuración necesaria en el firewall:** Sitio personalizado con el FQDN bloqueado configurado.  
_Notas de Check Point: Sitio personalizado de URL Filtering: se decide por Host (HTTP) y SNI/certificado (HTTPS). Por defecto www.example.org (bloqueado) y www.example.com (permitido) comparten IP._  
_Buena práctica de Check Point: Objetos de dominio no comodín para FQDN concretos; Application Control/URL Filtering para categorías._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-05.1 | FQDN permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering |
| POL-05.2 | FQDN bloqueado (HTTP) | Mismo hosting e IP: solo se bloquea si la decisión es por nombre. | Bloqueado | URL Filtering |
| POL-05.3 | FQDN bloqueado (HTTPS) | En HTTPS se decide por SNI/certificado. | Bloqueado | URL Filtering / TLS inspection |

### POL-06 · Reglas FQDN: rotación de IP, TTL y múltiples A/AAAA

**Prioridad:** Alta · _Manual_  
**Objetivo:** Las reglas por FQDN siguen las IP cambiantes de servicios en la nube.  
**Configuración necesaria en el firewall:** Regla con objeto de dominio (no comodín) y un destino con varias IP y TTL bajo.  
_Notas de Check Point: Objetos de dominio FQDN (no «wildcard») resuelven en el gateway; para SaaS conocidos, preferir objetos actualizables (Updatable Objects) del fabricante._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Crea una regla que permita un FQDN con varias A/AAAA y TTL bajo (p. ej. un servicio SaaS).
2. Desde un cliente resuelve y conecta repetidamente durante 30 min; anota las IP devueltas.
3. Comprueba que todas las conexiones se permiten y que los registros asocian el dominio.

**Resultado esperado:** Ninguna conexión legítima denegada por cambio de IP.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-07 · Fallos de DNS

**Prioridad:** Crítica  
**Objetivo:** Un fallo de resolución no abre conectividad.  
**Configuración necesaria en el firewall:** Ninguno.  
_Notas de Check Point: Sin resolución no hay flujo y la política sigue en denegación por defecto._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-07.1 | Nombre inexistente (NXDOMAIN) | curl a un nombre .invalid. | Sin flujo | Firewall |

### POL-08 · Etiquetas dinámicas AWS: alta, cambio y baja

**Prioridad:** Crítica · _Manual_  
**Objetivo:** La política sigue a las instancias por etiqueta en tiempo casi real.  
**Configuración necesaria en el firewall:** Conector de nube con lectura de EC2 y regla con objeto dinámico por etiqueta.  
_Notas de Check Point: CloudGuard Controller actualiza los objetos de datacenter sin instalar política (intervalo de escaneo configurable, por defecto 30 s)._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Crea un objeto dinámico «Environment=pro» y úsalo en una regla que permita un servicio.
2. Lanza una instancia con esa etiqueta y mide cuánto tarda en estar permitida.
3. Cambia la etiqueta y mide cuánto tarda en dejar de estarlo; termina la instancia y verifica que su IP sale del objeto.

**Resultado esperado:** Alta, cambio y baja reflejados sin reinstalar política, con tiempos medidos.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-09 · Etiquetas entre cuentas, regiones y entornos

**Prioridad:** Alta · _Manual_  
**Objetivo:** Los objetos por etiqueta funcionan con varias cuentas y regiones.  
**Configuración necesaria en el firewall:** Conector de nube con roles en varias cuentas (AssumeRole).  
_Notas de Check Point: Un objeto de datacenter AWS por cuenta (rol STS) y grupos que los combinan._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Registra dos cuentas (o una cuenta en dos regiones) en el conector de nube con roles de solo lectura.
2. Crea un objeto por etiqueta que incluya instancias de ambas y úsalo en una regla.
3. Verifica que el objeto contiene las IP de ambas cuentas y que la regla aplica.

**Resultado esperado:** Un mismo objeto cubre cuentas y regiones.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-10 · Precedencia de reglas

**Prioridad:** Crítica  
**Objetivo:** El orden de evaluación es determinista y la regla efectiva queda registrada.  
**Configuración necesaria en el firewall:** Roles precedence_clients y precedence_target, y la regla de excepción por encima de la de bloqueo.  
_Notas de Check Point: La política se evalúa de arriba abajo: una regla de excepción por encima de la de segmentación gana para su servicio; el resto lo decide la segmentación._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-10.1 | Servicio exceptuado hacia el destino bloqueado (solo desde el papel `precedence_clients`) | La regla de excepción está antes que la de bloqueo. | Permitido | Firewall |
| POL-10.2 | HTTP hacia el destino bloqueado (solo desde el papel `precedence_clients`) | Sin regla previa que lo permita, decide la de bloqueo. | Bloqueado | Firewall |

### POL-11 · Microsegmentación por servicio y entorno

**Prioridad:** Crítica  
**Objetivo:** No hay movimiento lateral fuera de la matriz aprobada.  
**Configuración necesaria en el firewall:** Matriz de segmentación en la configuración.  
_Notas de Check Point: Se ejecuta la matriz completa desde cada entorno (en lote sobre todos los clientes)._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-11.1 | Matriz completa de entornos | Matriz de segmentación configurada: desde este entorno hacia los demás se prueban ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 e iperf3, y se compara con lo permitido. | Según matriz | Firewall |

### POL-12 · Perfiles combinados

**Prioridad:** Alta  
**Objetivo:** Varios controles en el mismo flujo, cada uno con su traza.  
**Configuración necesaria en el firewall:** Perfil completo en la regla de salida y inspección TLS.  
_Notas de Check Point: En la salida a Internet se combinan Firewall, App Control, URL Filtering, IPS, Anti-Bot y Anti-Virus; el registro indica qué blade actuó._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-12.1 | EICAR desde Internet por HTTPS | Anti-Virus sobre HTTPS descifrado. | Bloqueado | Anti-malware / TLS inspection |
| POL-12.2 | Página de prueba de Anti-Bot | Reputación de C&C. | Bloqueado | Anti-bot (C&C) |
| POL-12.3 | Categoría Gambling | URL Filtering por categoría. | Bloqueado | URL Filtering |
| POL-12.4 | Sitio legítimo | Control: tráfico legítimo, no debe bloquearse. | Permitido | All |

### POL-13 · Reglas redundantes, ocultas y demasiado amplias

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se detectan reglas que nunca aplican o que permiten de más.  
**Configuración necesaria en el firewall:** Paquete de política con historial de tráfico.  
_Notas de Check Point: Policy Insights / Compliance blade (Best Practices) y hit count; evitar Any en servicio o destino en reglas Accept._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

**Procedimiento:**

1. Ejecuta el análisis de política del fabricante (reglas ocultas, redundantes, «any any»).
2. Cruza el resultado con POL-14 (reglas sin aciertos).
3. Documenta acciones: eliminar, acotar o justificar.

**Resultado esperado:** Lista de hallazgos con acción decidida para cada uno.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### POL-14 · Reglas sin uso

**Prioridad:** Media · _agente de control_  
**Objetivo:** Se identifican las reglas sin tráfico para revisarlas o eliminarlas.  
**Configuración necesaria en el firewall:** Contadores de aciertos activos en los gateways.  
_Notas de Check Point: Contadores de aciertos (hit count) de cada regla de las capas de acceso del paquete de política, por API de gestión._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-14.1 | Reglas sin aciertos y deshabilitadas | Lista de candidatas a limpieza. | Medida | Management |

### POL-15 · Modo detección frente a prevención

**Prioridad:** Alta  
**Objetivo:** El mismo estímulo solo se detecta en un destino y se bloquea en otro.  
**Configuración necesaria en el firewall:** Roles ids_target e ids_clients; regla TP con perfil Detect hacia ids_target; HTTP permitido desde ids_clients.  
_Notas de Check Point: Regla de Threat Prevention con perfil Detect hacia el entorno ids_target y perfil Prevent hacia el servidor._  
_Buena práctica de Check Point: Detect solo temporal (periodo de aprendizaje) y por entorno; pasar a Prevent con fecha._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-15.1 | SQLi hacia el destino en Detect (solo desde el papel `ids_clients`) | Llega al servidor y queda registrado como Detect. | Permitido | IPS |
| POL-15.2 | SQLi hacia el servidor en Prevent (solo desde el papel `ids_clients`) | Bloqueado y registrado como Prevent. | Bloqueado | IPS |

### POL-16 · Política declarativa y control de deriva

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Los cambios hechos fuera del flujo declarativo se detectan.  
**Configuración necesaria en el firewall:** La política se construye por código (scripts del kit o Terraform). Línea base guardada por el agente de control.  
_Notas de Check Point: Se compara la política publicada con una línea base (instantánea normalizada de las capas de acceso, amenazas e inspección HTTPS). Para demostrar la detección se añade por API una regla deshabilitada, se publica, se comprueba que aparece como deriva y se elimina._  
_Buena práctica de Check Point: Capas en secciones, objetos dinámicos (CloudGuard Controller) en lugar de IP, reglas con registro y caducidad para las excepciones._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| POL-16.1 | Detección de un cambio fuera de banda | Se publica un cambio temporal (regla deshabilitada) y se retira. | Cumple criterio | Management |

<a id="ips"></a>
## IPS · Prevención de intrusiones

### IPS-01 · Bloqueo de ataques conocidos

**Prioridad:** Crítica  
**Objetivo:** Las firmas detectan y bloquean; el registro incluye protección, severidad y acción.  
**Configuración necesaria en el firewall:** Perfil de prevención de amenazas con IPS en Prevent en la regla este-oeste.  
_Notas de Check Point: IPS en Prevent en todo el tráfico entre entornos y hacia Internet._  
_Buena práctica de Check Point: Optimized/Strict en Prevent con «Protections activation» por severidad y confianza._

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
**Configuración necesaria en el firewall:** Solo 80, 443 y el puerto de excepción permitidos hacia el servidor.  
_Notas de Check Point: El firewall descarta los puertos no autorizados aunque el servidor escuche; los intentos quedan registrados._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-02.1 | Escaneo de puertos al servidor | nmap sobre 1-1024, 3389, 5201 y 8080: solo deben verse los autorizados. | Solo autorizados | Firewall / IPS |

### IPS-03 · Configuración y actualización de firmas IPS

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Las firmas están al día y los perfiles activan las protecciones según criterios explícitos.  
**Configuración necesaria en el firewall:** Actualización automática de IPS en la gestión.  
_Notas de Check Point: Estado del paquete IPS (versión instalada, última disponible, fecha) y criterios de activación de los perfiles de prevención (impacto, severidad, confianza)._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-03.1 | Versión de firmas y perfiles | Firmas de menos de 7 días o sin actualización pendiente. | Cumple criterio | IPS |

### IPS-04 · Excepción de firma por activo

**Prioridad:** Crítica  
**Objetivo:** Solo queda exceptuada la combinación autorizada; el resto sigue protegido.  
**Configuración necesaria en el firewall:** Excepción en la regla este-oeste: protección «TP-Link Archer AX21 Command Injection (CVE-2023-1389)», origen = entorno ips_exception_client, acción Detect.  
_Notas de Check Point: Excepción de Threat Prevention con una sola protección (TP-Link Archer AX21, CVE-2023-1389), origen ips_exception_client y destino el servidor, en Detect._  
_Buena práctica de Check Point: Excepción por protección y activo concretos con caducidad; nunca desactivar la protección globalmente._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-04.1 | CVE-2023-1389 desde el activo exceptuado (solo desde el papel `ips_exception_client`) | Dentro del alcance: Detect. | Permitido | IPS |
| IPS-04.2 | CVE-2023-1389 desde otro activo | Fuera del alcance: sigue bloqueado. | Bloqueado | IPS |
| IPS-04.3 | Otra protección desde el activo exceptuado (solo desde el papel `ips_exception_client`) | El resto de protecciones siguen activas. | Bloqueado | IPS |

### IPS-05 · Falsos positivos

**Prioridad:** Alta  
**Objetivo:** Tráfico legítimo parecido a firmas no se bloquea.  
**Configuración necesaria en el firewall:** Ninguno.  
_Notas de Check Point: Perfiles por confianza e impacto; el ajuste fino se hace con excepciones por activo, sin desactivar detecciones globalmente._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

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
**Configuración necesaria en el firewall:** IPS en Prevent.  
_Notas de Check Point: El IPS bloquea la explotación de CVE conocidas; el servidor de pruebas no es vulnerable, solo recibe el patrón._  
_Buena práctica de Check Point: Revisar semanalmente las protecciones nuevas en Detect y promoverlas a Prevent._

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
**Configuración necesaria en el firewall:** IPS en Prevent.  
_Notas de Check Point: El IPS reensambla el flujo TCP y normaliza la codificación antes de buscar patrones._  
_Buena práctica de Check Point: Mantener activas las protecciones de evasión TCP/IP y de fragmentación (Inspection Settings)._

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
**Configuración necesaria en el firewall:** Regla de salida con los países bloqueados y una URL de prueba de uno de ellos (config.internet.geo_blocked_url).  
_Notas de Check Point: Objetos actualizables GEO en la capa de salida._  
_Buena práctica de Check Point: Geo Policy o regla con objetos de país actualizables al principio de la capa de salida._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-08.1 | Destino en país bloqueado | IP de destino en un país bloqueado. | Bloqueado | Firewall (GEO) |
| IPS-08.2 | Destino en país permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | Firewall (GEO) |

### IPS-09 · C&C y botnets

**Prioridad:** Alta  
**Objetivo:** El tráfico hacia indicadores de C&C se bloquea.  
**Configuración necesaria en el firewall:** Anti-Bot en el perfil de salida.  
_Notas de Check Point: Anti-Bot bloquea por reputación de dominio, IP y URL (ThreatCloud) y por patrones de comunicación._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-09.1 | URL de prueba de C&C del fabricante | URL de prueba que el fabricante clasifica como C&C (configurable en Destinos en Internet). | Bloqueado | Anti-bot (C&C) |
| IPS-09.2 | Control: sitio corporativo permitido | Control: tráfico legítimo, no debe bloquearse. | Permitido | Anti-bot (C&C) |

### IPS-10 · Tiempo de reacción a amenazas y propagación

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Un indicador de compromiso nuevo se aplica en los gateways en un tiempo medido.  
**Configuración necesaria en el firewall:** Anti-bot activo en la salida a Internet. Dominio de prueba en internet.ioc_test_domain (se fuerza su resolución a la IP del sitio permitido).  
_Notas de Check Point: Se crea por API un indicador (dominio, Prevent), se publica e instala la política de amenazas y un cliente intenta conectar a ese dominio hasta que se bloquea; luego se elimina._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| IPS-10.1 | De indicador nuevo a bloqueo efectivo | Instala la política de amenazas dos veces en los gateways de prueba. | Cumple criterio | Anti-bot (C&C) |

### IPS-11 · Política diferenciada IDS frente a IPS

**Prioridad:** Alta  
**Objetivo:** El modo detección no bloquea; el de prevención sí; ambos registran.  
**Configuración necesaria en el firewall:** Igual que POL-15.  
_Notas de Check Point: Mismo estímulo contra el destino en Detect (ids_target) y contra el servidor en Prevent._  
_Buena práctica de Check Point: Perfil Optimized/Strict en Prevent, actualizaciones automáticas, excepciones acotadas por activo y protección (nunca globales) y Inactive solo para tecnologías inexistentes (p. ej. OT/SCADA por etiqueta)._

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
**Configuración necesaria en el firewall:** Anti-Virus con inspección en ambos sentidos y de archivos comprimidos.  
_Notas de Check Point: Anti-Virus (firmas + ThreatCloud) en HTTP/HTTPS, incluidos comprimidos anidados y subidas._  
_Buena práctica de Check Point: Anti-Virus en ambos sentidos con inspección de comprimidos, Threat Emulation + Threat Extraction para documentos y Anti-Bot en Prevent._

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
**Configuración necesaria en el firewall:** inspección TLS con bypass para nodecrypt.testkit.lab y mtls.testkit.lab.  
_Notas de Check Point: Mismo EICAR por HTTPS al mismo servidor con dos nombres: inspect.testkit.lab (descifrado) y nodecrypt.testkit.lab (excluido)._  
_Buena práctica de Check Point: Sin descifrado el anti-malware solo ve el SNI: descifrar el tráfico de descarga._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-02.1 | EICAR por HTTP | Descarga desde el servidor; Anti-Virus inspecciona ficheros en ambos sentidos y dentro de comprimidos. | Bloqueado | Anti-malware |
| THR-02.2 | EICAR por HTTPS descifrado | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| THR-02.3 | EICAR por HTTPS sin descifrar | Sin descifrado no hay visibilidad del contenido (resultado esperado). | Permitido | TLS inspection (bypass) |
| THR-02.4 | EICAR desde Internet por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |

### THR-03 · Ficheros benignos sin falsos positivos

**Prioridad:** Alta  
**Objetivo:** Ficheros limpios de varios formatos y tamaños no se bloquean.  
**Configuración necesaria en el firewall:** Ninguno.  
_Notas de Check Point: Descargas por HTTP y HTTPS._  
_Buena práctica de Check Point: Anti-Virus en ambos sentidos con inspección de comprimidos, Threat Emulation + Threat Extraction para documentos y Anti-Bot en Prevent._

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

### THR-04 · Emulación/sandbox de fichero de prueba

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** Los ficheros desconocidos se analizan en sandbox antes de entregarse.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita la capacidad de sandbox (emulación) licenciada y un fichero de prueba del fabricante.  
_Notas de Check Point: Threat Emulation (ThreatCloud) en Prevent + Threat Extraction para documentos (entrega inmediata de una copia limpia)._  
_Buena práctica de Check Point: Anti-Virus en ambos sentidos con inspección de comprimidos, Threat Emulation + Threat Extraction para documentos y Anti-Bot en Prevent._

**Procedimiento:**

1. Activa la emulación en el perfil de amenazas en modo Prevent (retener el fichero hasta el veredicto).
2. Descarga desde un cliente un fichero de prueba de emulación del fabricante y un documento benigno nuevo.
3. Comprueba el veredicto, el tiempo de entrega y el informe de emulación.

**Resultado esperado:** Fichero malicioso bloqueado con informe; benigno entregado con tiempo medido.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### THR-05 · AV, Anti-Bot e IPS combinados

**Prioridad:** Alta  
**Objetivo:** Los controles combinados no se anulan y muestran quién actuó.  
**Configuración necesaria en el firewall:** Perfil completo y inspección TLS.  
_Notas de Check Point: Varios blades en el mismo perfil._  
_Buena práctica de Check Point: Anti-Virus en ambos sentidos con inspección de comprimidos, Threat Emulation + Threat Extraction para documentos y Anti-Bot en Prevent._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-05.1 | EICAR en zip por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| THR-05.2 | SQLi por HTTPS | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| THR-05.3 | C&C por HTTP | Anti-Bot. | Bloqueado | Anti-bot (C&C) |

### THR-06 · Actualización e inteligencia de amenazas

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Las bases de anti-malware, anti-bot, URL y aplicaciones están actualizadas en cada gateway.  
**Configuración necesaria en el firewall:** Acceso de los gateways a los servicios de actualización del fabricante.  
_Notas de Check Point: Estado de actualización de cada base en los gateways (run-script) y de los objetos actualizables (GEO, servicios en línea)._  
_Buena práctica de Check Point: Anti-Virus en ambos sentidos con inspección de comprimidos, Threat Emulation + Threat Extraction para documentos y Anti-Bot en Prevent._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| THR-06.1 | Estado de actualización por gateway | Cualquier base con error o sin actualizar es un fallo. | Cumple criterio | Anti-malware / Anti-bot (C&C) |

<a id="tls"></a>
## TLS · Inspección y cifrado TLS

### TLS-01 · Inspección TLS 1.2 y 1.3

**Prioridad:** Crítica  
**Objetivo:** Se documenta qué versiones se inspeccionan y se bloquean patrones dentro de ellas.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTPS Inspection inspecciona TLS 1.2 y 1.3 re-firmando con la CA de inspección._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

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
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: La CA de inspección se distribuye a los clientes; un cliente sin ella recibe un error de certificado._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-02.1 | Certificado sustituido en Internet | La web llega firmada por la CA de inspección. | Descifrado | TLS inspection |
| TLS-02.2 | Cliente con la CA de inspección | Valida con la CA de inspección en su almacén. | Cert. válido | TLS inspection |
| TLS-02.3 | Cliente sin la CA de inspección | Solo CA públicas: falla. | Cert. rechazado | TLS inspection |

### TLS-03 · Certificados caducados, revocados o no confiables

**Prioridad:** Alta  
**Objetivo:** La respuesta coincide con la política de validación y queda registrada.  
**Configuración necesaria en el firewall:** HTTPS advanced settings: bloquear no confiables, caducados y revocados.  
_Notas de Check Point: HTTPS Inspection valida el certificado original y bloquea los no confiables, caducados y revocados._  
_Buena práctica de Check Point: Bloquear certificados caducados, no confiables y revocados (validación del servidor en la capa HTTPS)._

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
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: mTLS y pinning no admiten intermediario: se excluyen del descifrado solo esos FQDN._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-04.1 | mTLS con certificado de cliente (excluido) | El servidor exige certificado de cliente. | Permitido | TLS inspection (bypass) |
| TLS-04.2 | Pinning de CA (excluido) | Cliente que solo confía en la CA del servicio. | Cert. válido | TLS inspection (bypass) |
| TLS-04.3 | Pinning de CA (inspeccionado) | Contra el FQDN inspeccionado falla: el pinning requiere exclusión. | Cert. rechazado | TLS inspection |

### TLS-05 · Exclusiones de descifrado por FQDN y categoría

**Prioridad:** Crítica  
**Objetivo:** Solo el alcance aprobado queda sin descifrar.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Exclusiones por FQDN, por categorías sensibles (finanzas, salud, gobierno) y por la lista recomendada de Check Point._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-05.1 | FQDN excluido | No se descifra. | Sin descifrar | TLS inspection |
| TLS-05.2 | FQDN inspeccionado | Se descifra. | Descifrado | TLS inspection |
| TLS-05.3 | Banca (categoría Financial) | Categoría sensible excluida. | Sin descifrar | TLS inspection |
| TLS-05.4 | Web general | Se descifra. | Descifrado | TLS inspection |

### TLS-06 · HTTP/2, QUIC y ECH

**Prioridad:** Alta  
**Objetivo:** Se conoce la visibilidad efectiva y no hay bypass silencioso.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTP/2 se inspecciona igual que HTTP/1.1; QUIC (UDP/443) se deniega para forzar TCP inspeccionado._  
_Buena práctica de Check Point: Bloquear QUIC (UDP/443) para forzar HTTP/2 sobre TLS inspeccionable._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-06.1 | SQLi por HTTP/2 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | IPS / TLS inspection |
| TLS-06.2 | EICAR por HTTP/2 | Petición HTTPS al servidor con SNI inspect.testkit.lab: inspección TLS descifra y los blades inspeccionan el contenido. | Bloqueado | Anti-malware / TLS inspection |
| TLS-06.3 | Petición limpia por HTTP/2 | Control: tráfico legítimo, no debe bloquearse. | Permitido | TLS inspection |
| TLS-06.4 | QUIC (UDP/443) a Internet | Paquete QUIC Initial: sin respuesta. | Bloqueado | Firewall |

### TLS-07 · Modo transparente y observabilidad

**Prioridad:** Media  
**Objetivo:** Se conoce el impacto sobre la IP de origen.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Detrás de GWLB el firewall es transparente: conserva la IP original y no añade cabeceras de proxy._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-07.1 | IP de origen conservada (HTTPS inspeccionado) | El servidor devuelve la IP y cabeceras que ve. | IP conservada | TLS inspection |

### TLS-08 · Sobrecoste de la inspección TLS

**Prioridad:** Crítica  
**Objetivo:** Se obtiene el sobrecoste real de handshake y latencia.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: 100 conexiones HTTPS nuevas con y sin descifrado al mismo servidor; se comparan percentiles._  
_Buena práctica de Check Point: Dimensionar la inspección TLS con PERF-02; bypass de categorías de confianza de alto volumen (actualizaciones del SO, backups)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| TLS-08.1 | Sobrecoste de inspección TLS | inspect.testkit.lab frente a nodecrypt.testkit.lab. | Medida | TLS inspection |

### TLS-09 · Amenazas dentro de HTTPS (este-oeste)

**Prioridad:** Alta  
**Objetivo:** Las cargas de IPS y AV dentro de HTTPS se bloquean igual que en HTTP.  
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: HTTPS Inspection este-oeste devuelve la visibilidad a IPS, AV y DLP._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

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
**Configuración necesaria en el firewall:** inspección TLS (outbound) con la CA de inspección distribuida a los clientes y la CA del kit como CA de confianza.  
_Notas de Check Point: Con HTTPS Inspection el gateway ve el Host real, descomprime gzip, reensambla chunked/multipart y valida el protocolo por puerto._  
_Buena práctica de Check Point: Inspección HTTPS con capa propia, bypass por objeto actualizable recomendado (sk163595) y categorías sensibles, TLS 1.3 y validación de certificados._

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
**Configuración necesaria en el firewall:** Servicios HTTP/HTTPS con identificación por protocolo (no solo por puerto) y SSH bloqueado como aplicación.  
_Notas de Check Point: App Control identifica aplicaciones en cualquier puerto y la salida solo admite HTTP/HTTPS con firma de protocolo._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

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
**Configuración necesaria en el firewall:** Categorías Gambling y Anonymizer, y aplicaciones Facebook, TikTok, Dropbox y WeTransfer bloqueadas; LinkedIn permitida.  
_Notas de Check Point: URL Filtering por categorías y App Control por aplicación, en HTTP y HTTPS._  
_Buena práctica de Check Point: Bloquear categorías de alto riesgo, anonimizadores y P2P; UserCheck para las de riesgo medio._

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
**Configuración necesaria en el firewall:** Sitio personalizado con la ruta bloqueada configurada (config.internet.blocked_path).  
_Notas de Check Point: Con HTTPS Inspection se ve la URL completa y se puede bloquear una ruta; sin descifrado solo el dominio._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-03.1 | Ruta permitida por HTTP | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering |
| APP-03.2 | Ruta bloqueada por HTTP | Coincide la ruta. | Bloqueado | URL Filtering |
| APP-03.3 | Ruta permitida por HTTPS | Control: tráfico legítimo, no debe bloquearse. | Permitido | URL Filtering / TLS inspection |
| APP-03.4 | Ruta bloqueada por HTTPS | Solo posible con descifrado. | Bloqueado | URL Filtering / TLS inspection |

### APP-04 · Filtrado independiente del DNS

**Prioridad:** Alta  
**Objetivo:** Se conoce la superficie cubierta: IP directa, sin SNI, DoH y DoT.  
**Configuración necesaria en el firewall:** Aplicación DoH bloqueada; solo DNS/HTTP/HTTPS en la salida.  
_Notas de Check Point: Identificación por Host, SNI y certificado; DoH bloqueado como aplicación y DoT por puerto._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-04.1 | Facebook por IP con cabecera Host | Sin consulta DNS. | Bloqueado | Application control |
| APP-04.2 | Facebook por IP sin SNI (HTTPS) | Se clasifica por el certificado. | Bloqueado | Application control / TLS inspection |
| APP-04.3 | DNS sobre HTTPS | Aplicación DoH. | Bloqueado | Application control |
| APP-04.4 | DNS sobre TLS (tcp/853) | DoT por su puerto estándar. | Bloqueado | Firewall |

### APP-05 · Línea base de tráfico anómalo

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Se establece el comportamiento normal y se detectan desviaciones.  
**Configuración necesaria en el firewall:** Al menos una semana de registros.  
_Notas de Check Point: SmartEvent / Infinity XDR/XPR con correlación de anomalías; vistas de Logs & Monitor por aplicación y volumen._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

**Procedimiento:**

1. Con una semana de registros, obtén el top de aplicaciones, destinos y volúmenes por entorno.
2. Genera una desviación (p. ej. transferencia grande nocturna a un destino nuevo con el kit).
3. Verifica que aparece en informes/alertas de anomalías.

**Resultado esperado:** La desviación se detecta y se puede investigar.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### APP-06 · Picos, beaconing y conexiones anómalas

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se detectan patrones de beaconing y picos de conexiones.  
**Configuración necesaria en el firewall:** Anti-bot activo y correlación de eventos.  
_Notas de Check Point: Anti-Bot (comportamiento C&C) + SmartEvent/Infinity XDR; protección IPS «Port Scan»._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

**Procedimiento:**

1. Desde un cliente, genera una conexión periódica (cada 60 s, mismo tamaño) a un destino externo durante 1 h.
2. Genera un pico de conexiones (p. ej. PERF-06) y un escaneo (IPS-02).
3. Revisa qué eventos se generan y con qué severidad.

**Resultado esperado:** Beaconing, pico y escaneo identificados con evidencia.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### APP-07 · Conexiones salientes inesperadas

**Prioridad:** Alta  
**Objetivo:** Un servidor no puede abrir conexiones a destinos y puertos no previstos.  
**Configuración necesaria en el firewall:** Capa de salida con cleanup en Drop.  
_Notas de Check Point: Salida denegada por defecto; cada intento queda registrado._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| APP-07.1 | SQL Server tcp/1433 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.2 | MySQL tcp/3306 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.3 | PostgreSQL tcp/5432 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.4 | SMTP tcp/25 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |
| APP-07.5 | SMB tcp/445 a Internet | Puerto no previsto hacia Internet. | Bloqueado | Firewall |

### APP-08 · Rate limiting y mitigación básica de abuso

**Prioridad:** Media · _Manual_  
**Objetivo:** Se puede limitar la tasa de conexiones de un origen abusivo.  
**Configuración necesaria en el firewall:** Capacidad de limitación de tasa en el firewall.  
_Notas de Check Point: Rate limiting con «fw samp add quota» (Accelerated DoS/Rate Limiting, sk112454) o protección IPS de inundación._  
_Buena práctica de Check Point: Capa en línea de salida con Application Control y URL Filtering, categorías de alto riesgo bloqueadas y servicios con firma de protocolo._

**Procedimiento:**

1. Configura un límite de conexiones por segundo por origen hacia el servidor de pruebas.
2. Lanza PERF-05 (CPS) desde un cliente y comprueba que la tasa se limita y queda registrado.
3. Retira el límite y repite para comparar.

**Resultado esperado:** Tasa limitada al valor configurado y evento registrado.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="dlp"></a>
## DLP · Prevención de fuga de datos

### DLP-01 · Transferencia de datos sensibles

**Prioridad:** Media  
**Objetivo:** Se detectan y bloquean patrones sensibles sintéticos.  
**Configuración necesaria en el firewall:** Reglas de DLP (inspección de contenido) (PCI, IBAN, ejecutables) entre entornos sobre HTTP y HTTPS.  
_Notas de Check Point: Content Awareness con tipos de datos PCI e IBAN y tipo de fichero ejecutable._  
_Buena práctica de Check Point: Content Awareness en las reglas este-oeste y de salida, con HTTPS descifrado._

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
**Configuración necesaria en el firewall:** Rol dlp_exception_client y regla de excepción con dirección 'up'.  
_Notas de Check Point: Regla de excepción (solo subida desde dlp_exception_client al servidor) por encima de la de bloqueo._  
_Buena práctica de Check Point: Content Awareness en la capa de red con tipos de datos predefinidos (PCI, IBAN) y excepciones por activo y sentido._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| DLP-02.1 | Subida PCI desde el activo exceptuado (solo desde el papel `dlp_exception_client`) | Dentro del alcance. | Permitido | DLP |
| DLP-02.2 | Subida PCI desde otro activo | Mismo fichero y destino desde otro activo. | Bloqueado | DLP |
| DLP-02.3 | Descarga PCI hacia el activo exceptuado (solo desde el papel `dlp_exception_client`) | La excepción solo cubre la subida. | Bloqueado | DLP |

### DLP-03 · DLP sobre tráfico cifrado y distintos tamaños

**Prioridad:** Media  
**Objetivo:** Se documentan los límites por formato, cifrado y tamaño.  
**Configuración necesaria en el firewall:** Reglas de DLP (inspección de contenido) (PCI, IBAN, ejecutables) entre entornos sobre HTTP y HTTPS.  
_Notas de Check Point: Content Awareness sobre HTTPS descifrado, ficheros grandes y Office._  
_Buena práctica de Check Point: Content Awareness en la capa de red con tipos de datos predefinidos (PCI, IBAN) y excepciones por activo y sentido._

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
**Configuración necesaria en el firewall:** IPS en Prevent.  
_Notas de Check Point: El IPS cubre las clases comunes de ataque web. La protección completa de aplicaciones y API (incluidas tautologías en formularios y JSON) corresponde a Check Point CloudGuard WAF._  
_Buena práctica de Check Point: IPS para la red; aplicaciones web y API publicadas detrás de CloudGuard WAF._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| WAF-01.1 | SQLi en parámetro GET | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| WAF-01.2 | XSS reflejado | Petición HTTP al servidor de pruebas con un patrón de ataque conocido: el IPS en Prevent debe cortar la conexión. | Bloqueado | IPS |
| WAF-01.3 | Tautología SQL en formulario POST (informativa) | Clase propia de un WAF: informativa. | Bloqueado | IPS → WAF |
| WAF-01.4 | Tautología SQL en JSON (API) (informativa) | Clase propia de un WAF: informativa. | Bloqueado | IPS → WAF |

### WAF-02 · Excepciones, ajuste y actualización de políticas WAF

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** El WAF se ajusta sin abrir huecos y se actualiza solo.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita una aplicación web publicada detrás de un WAF.  
_Notas de Check Point: CloudGuard WAF (motor de aprendizaje contextual, sin firmas que mantener) con excepciones por parámetro._  
_Buena práctica de Check Point: IPS para la red; aplicaciones web y API publicadas detrás de CloudGuard WAF._

**Procedimiento:**

1. Publica una aplicación de prueba con WAF en modo aprendizaje y luego en prevención.
2. Genera un falso positivo y crea una excepción acotada (parámetro/URL).
3. Repite los ataques de WAF-01 y comprueba que siguen bloqueados.

**Resultado esperado:** Excepción acotada y ataques bloqueados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### WAF-03 · Protección de API / HTTP y TLS

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** Las API publicadas se protegen por esquema y contra abuso.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita una API publicada detrás de un WAF.  
_Notas de Check Point: CloudGuard WAF con validación de esquema OpenAPI y limitación de tasa._  
_Buena práctica de Check Point: IPS para la red; aplicaciones web y API publicadas detrás de CloudGuard WAF._

**Procedimiento:**

1. Publica una API con su esquema OpenAPI detrás del WAF.
2. Envía peticiones fuera de esquema, inyecciones en JSON y abuso de tasa.
3. Comprueba bloqueos y registros.

**Resultado esperado:** Peticiones fuera de esquema y abuso bloqueados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="obs"></a>
## OBS · Visibilidad y auditoría

### OBS-01 · Registros allow/deny por conexión

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Cada conexión permitida o denegada deja un registro completo y consultable.  
**Configuración necesaria en el firewall:** Registro activado en las reglas de segmentación y en la de limpieza.  
_Notas de Check Point: Un cliente abre una conexión permitida (tcp/80) y otra denegada (tcp/22) al servidor y el agente de control las busca en los registros por API, midiendo cuánto tardan en aparecer y qué campos traen._  
_Buena práctica de Check Point: Registro en todas las reglas; en reglas de mucho volumen, registro acumulado (accounting) en lugar de por conexión si el SIEM lo requiere._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| OBS-01.1 | Registro de conexión permitida y denegada | Campos: hora, acción, regla, capa, origen, destino, servicio y gateway. | Cumple criterio | Logging |

### OBS-02 · Trazabilidad de protecciones NGFW

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Los eventos de IPS, anti-malware y filtrado URL identifican la protección, severidad, confianza y regla.  
**Configuración necesaria en el firewall:** IPS, anti-malware y filtrado URL en Prevent con registro.  
_Notas de Check Point: Un cliente genera un ataque SQLi, una descarga EICAR y un acceso a un FQDN bloqueado; el agente de control busca los eventos y comprueba sus campos._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| OBS-02.1 | Eventos de IPS, anti-malware y URL | El evento debe nombrar la protección y su severidad. | Cumple criterio | Logging |

### OBS-03 · Auditoría de cambios API/UI/IaC

**Prioridad:** Alta · _Manual_  
**Objetivo:** Cada cambio de configuración queda registrado con quién, qué y cuándo.  
**Configuración necesaria en el firewall:** Registro de auditoría de la gestión activo.  
_Notas de Check Point: Logs & Monitor → Audit; una clave API por automatización (nunca compartida) y nombre de sesión descriptivo._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Haz un cambio por la consola, otro por la API (p. ej. OPS-03) y otro por Terraform.
2. Busca los tres en el registro de auditoría y compara los detalles (usuario/clave API, sesión, objeto, antes/después).

**Resultado esperado:** Los tres cambios aparecen con autor, hora y detalle.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-04 · Exportación a SIEM y calidad de eventos

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Los eventos llegan al SIEM completos, normalizados y a tiempo.  
**Configuración necesaria en el firewall:** SIEM o colector syslog accesible desde la gestión.  
_Notas de Check Point: Log Exporter (CEF, LEEF, JSON) o conectores de Infinity Events para SIEM; TLS hacia el colector._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Configura la exportación de registros (syslog CEF/LEEF o API) hacia el SIEM.
2. Ejecuta OBS-01 y OBS-02 y localiza esos eventos en el SIEM.
3. Mide la latencia y compara campos con el registro original.

**Resultado esperado:** Eventos completos en el SIEM con latencia medida.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-05 · Correlación con VPC/TGW Flow Logs

**Prioridad:** Alta · _Manual_  
**Objetivo:** Los registros del firewall se pueden cruzar con los flow logs de la nube.  
**Configuración necesaria en el firewall:** Flow logs activos en las VPC de spokes y en el TGW.  
_Notas de Check Point: GWLB conserva la IP de origen; mantener los relojes en NTP para correlar._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Activa VPC/TGW Flow Logs.
2. Ejecuta NET-01 y busca la misma conexión (5-tupla y hora) en ambos registros.
3. Comprueba que las IP de origen se conservan (sin NAT en el camino este-oeste).

**Resultado esperado:** La misma conexión se identifica en ambos registros.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-06 · Captura de paquetes y diagnóstico de sesiones

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se puede capturar y diagnosticar una sesión concreta.  
**Configuración necesaria en el firewall:** Acceso administrativo a los gateways.  
_Notas de Check Point: «fw monitor -F» / «tcpdump», «fw ctl zdebug drop» y captura de paquetes en los registros (track-settings packet capture)._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Abre una captura filtrada por la IP de un cliente en el gateway.
2. Ejecuta una comprobación del kit y descarga la captura.
3. Usa la herramienta de depuración de decisiones para ver qué regla aplicó.

**Resultado esperado:** Captura y diagnóstico obtenidos sin interrumpir el servicio.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-07 · Visibilidad de activos, etiquetas, VPC, cuenta y región

**Prioridad:** Alta · _Manual_  
**Objetivo:** Los registros y la consola muestran el contexto de nube del activo.  
**Configuración necesaria en el firewall:** Conector de nube configurado.  
_Notas de Check Point: Objetos de datacenter de CloudGuard Controller en reglas y registros; CloudGuard CNAPP para inventario completo._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Consulta en la consola el inventario de activos importado de la nube.
2. Abre un registro del kit y comprueba si muestra nombre de instancia, etiquetas, VPC, cuenta o región.

**Resultado esperado:** Contexto de nube visible para investigar sin salir de la consola.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-08 · Monitorización de salud, recursos y alertas

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Se conoce el estado de cada gateway y hay alertas configuradas.  
**Configuración necesaria en el firewall:** Agente de control en marcha con credenciales de la nube (lectura; las pruebas de HA cambian el grupo de autoescalado y las ACL de red) y de la API de gestión.  
_Notas de Check Point: Nube: estado del grupo de autoescalado y de los destinos del balanceador, métricas de CPU y alarmas. Gateways: CPU, memoria, conexiones, disco y procesos._  
_Buena práctica de Check Point: Alarmas de CloudWatch de CPU (escalado) y de destinos no sanos del GWLB; SNMPv3/monitorización de Gaia._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| OBS-08.1 | Salud en la nube y alarmas | Destinos sanos, métricas y al menos una alarma. | Cumple criterio | Monitoring |
| OBS-08.2 | Salud de los gateways | Ningún proceso caído. | Cumple criterio | Monitoring |

### OBS-09 · Registros bajo presión y retención

**Prioridad:** Alta · _Manual_  
**Objetivo:** No se pierden registros con carga alta y la retención cumple lo requerido.  
**Configuración necesaria en el firewall:** Carga de PERF-05/PERF-06 disponible.  
_Notas de Check Point: Smart-1 Cloud: retención según suscripción; registros acumulados en el gateway si se pierde la conexión con la gestión._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Lanza PERF-05 (miles de conexiones nuevas) y cuenta las conexiones generadas.
2. Cuenta los registros correspondientes en la consola y calcula el porcentaje.
3. Revisa la política de retención contratada/configurada.

**Resultado esperado:** ≥ 99 % de registros y retención documentada.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-10 · Telemetría Syslog/SNMP/NetFlow

**Prioridad:** Media · _Manual_  
**Objetivo:** El firewall exporta telemetría estándar.  
**Configuración necesaria en el firewall:** Colectores de syslog/SNMP/NetFlow.  
_Notas de Check Point: Gaia: SNMPv3, NetFlow export y syslog remoto; en gateways de autoescalado se aplican por script de inicio o plantilla de CME._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Configura en los gateways el envío de SNMP (v3), NetFlow/IPFIX y syslog del sistema.
2. Comprueba en los colectores que llegan datos y que son coherentes con la carga del kit.

**Resultado esperado:** Telemetría recibida y coherente.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OBS-11 · Informes de investigación y búsqueda por filtros

**Prioridad:** Media · _Manual_  
**Objetivo:** Se encuentra rápido lo ocurrido con un activo o ataque.  
**Configuración necesaria en el firewall:** Registros de una ejecución completa del kit.  
_Notas de Check Point: Logs & Monitor (consultas guardadas), informes de Infinity Events/SmartEvent._  
_Buena práctica de Check Point: Registro en todas las reglas, Log Exporter al SIEM y SmartEvent/Infinity Events; captura de paquetes en las reglas de amenazas._

**Procedimiento:**

1. Tras una ejecución completa, busca por IP de origen, protección y franja horaria.
2. Genera un informe de amenazas del periodo y exporta.

**Resultado esperado:** Búsquedas en segundos e informe exportable.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="ha"></a>
## HA · Disponibilidad y resiliencia

### HA-01 · Caída de instancia de inspección

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** La pérdida de un gateway se detecta, el servicio continúa y el grupo lo reemplaza con la política aplicada.  
**Configuración necesaria en el firewall:** Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).  
_Notas de Check Point: Se termina un gateway en el grupo de autoescalado. Se miden: detección en el GWLB, lanzamiento y alta del sustituto, registro en la gestión con política (CME) y retirada del objeto antiguo. Mientras dura el evento, cada cliente sondea cada segundo el servidor (este-oeste), Internet y un flujo denegado; se mide la interrupción más larga y se comprueba que el flujo denegado nunca pasa. Los fallos se simulan de forma reversible: ACL de red con denegación de la IP del gateway (/32) y procesos de salud del grupo suspendidos durante la prueba._  
_Buena práctica de Check Point: Mínimo n+1 por AZ y health check del GWLB en el puerto del gateway (8117)._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| HA-01.1 | Terminar un gateway y medir la recuperación | Criterio: sustituto en servicio con política e interrupción ≤ ha.max_outage_s. | Cumple criterio | Availability |

### HA-02 · Fallo de una zona de disponibilidad

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Si caen los gateways de una AZ, los de la otra mantienen el servicio.  
**Configuración necesaria en el firewall:** Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).  
_Notas de Check Point: Se aíslan todos los gateways de una AZ durante ha.isolation_s y se restauran. Se informa del balanceo entre zonas y del comportamiento ante destinos no sanos del GWLB. Mientras dura el evento, cada cliente sondea cada segundo el servidor (este-oeste), Internet y un flujo denegado; se mide la interrupción más larga y se comprueba que el flujo denegado nunca pasa. Los fallos se simulan de forma reversible: ACL de red con denegación de la IP del gateway (/32) y procesos de salud del grupo suspendidos durante la prueba._  
_Buena práctica de Check Point: Cross-zone activado en el GWLB para que una AZ sin gateways use los de la otra._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| HA-02.1 | Aislar los gateways de una AZ | Criterio: interrupción ≤ ha.max_outage_s y recuperación al restaurar. | Cumple criterio | Availability |

### HA-03 · Comportamiento fail-closed ante fallo de inspección

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Si no hay inspección disponible, el tráfico se corta: nunca pasa sin inspeccionar.  
**Configuración necesaria en el firewall:** Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).  
_Notas de Check Point: Se aíslan todos los gateways a la vez (plano de datos de inspección caído) y se cuenta cualquier flujo que llegue a pasar mientras tanto; después se restaura y se mide la recuperación. Mientras dura el evento, cada cliente sondea cada segundo el servidor (este-oeste), Internet y un flujo denegado; se mide la interrupción más larga y se comprueba que el flujo denegado nunca pasa. Los fallos se simulan de forma reversible: ACL de red con denegación de la IP del gateway (/32) y procesos de salud del grupo suspendidos durante la prueba._  
_Buena práctica de Check Point: ASG en ≥ 2 AZ con mínimo n+1, GWLB cross-zone, CME con plantilla y política, y comprobación de actualizaciones (THR-06) en cada gateway nuevo._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| HA-03.1 | Aislar todo el plano de inspección | Criterio: cero flujos sin inspección y recuperación al restaurar. | Cumple criterio | Availability |

### HA-04 · Failover y persistencia de sesiones stateful

**Prioridad:** Crítica · _agente de control_  
**Objetivo:** Se documenta qué sesiones establecidas sobreviven a la pérdida de un gateway.  
**Configuración necesaria en el firewall:** Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).  
_Notas de Check Point: Cada cliente mantiene 20 sesiones HTTP keep-alive (una petición cada 2 s) durante la pérdida de gateways de HA-01/HA-02 (o un aislamiento propio si se ejecuta sola) y se cuenta cuántas sobreviven._  
_Buena práctica de Check Point: Las sesiones del gateway perdido se cortan (sin sincronización de estado en autoescalado): aplicaciones con reintento; «target failover rebalance» acelera el cambio de los flujos._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| HA-04.1 | Sesiones largas durante la pérdida de un gateway | Medida: sesiones supervivientes y cortadas. | Medida | Availability |

### HA-05 · Escalado horizontal hacia arriba y retorno

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Un gateway nuevo entra en servicio con política sin cortar el tráfico y se retira limpiamente.  
**Configuración necesaria en el firewall:** Grupo de autoescalado con al menos 2 gateways en 2 AZ detrás del Gateway Load Balancer. Agente de control con permisos sobre el grupo y las ACL de red. Todos los clientes en línea (sondas continuas).  
_Notas de Check Point: Se sube en uno la capacidad deseada del grupo (protegiendo los gateways existentes), se mide el alta (instancia, destino sano, registro con política) y se vuelve a la capacidad inicial midiendo la baja (desregistro, terminación, objeto retirado). Mientras dura el evento, cada cliente sondea cada segundo el servidor (este-oeste), Internet y un flujo denegado; se mide la interrupción más larga y se comprueba que el flujo denegado nunca pasa. Los fallos se simulan de forma reversible: ACL de red con denegación de la IP del gateway (/32) y procesos de salud del grupo suspendidos durante la prueba._  
_Buena práctica de Check Point: Política de escalado por CPU (p. ej. 70 %/30 %) y CME con la plantilla para que cada gateway nuevo reciba la política._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| HA-05.1 | Escalar +1 y volver | Incluye las políticas de escalado configuradas. | Cumple criterio | Availability |

### HA-06 · Actualización blue/green y mantenimiento

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se actualiza la versión de los gateways sin cortar el servicio.  
**Configuración necesaria en el firewall:** Plantilla de lanzamiento versionada del grupo de autoescalado.  
_Notas de Check Point: Instance refresh con «minimum healthy 100 %» o grupo blue/green; CME aprovisiona los nuevos gateways con la misma plantilla._  
_Buena práctica de Check Point: ASG en ≥ 2 AZ con mínimo n+1, GWLB cross-zone, CME con plantilla y política, y comprobación de actualizaciones (THR-06) en cada gateway nuevo._

**Procedimiento:**

1. Con las sondas de HA en marcha, cambia la imagen/versión en la plantilla del grupo.
2. Lanza un instance refresh (o un grupo nuevo en paralelo) y deja que los gateways se sustituyan de uno en uno.
3. Mide interrupciones y confirma la versión y política de los nuevos gateways.

**Resultado esperado:** Sustitución progresiva sin interrupción por encima del umbral de HA.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### HA-07 · Resiliencia ante fallo de DNS o del plano de control

**Prioridad:** Alta · _Manual_  
**Objetivo:** Si la gestión o el DNS fallan, el tráfico sigue inspeccionado con la última política.  
**Configuración necesaria en el firewall:** Posibilidad de cortar la conexión gateway–gestión de forma controlada.  
_Notas de Check Point: El gateway conserva la política local y acumula registros; las reglas por dominio dependen del DNS del gateway (usar resolvedores redundantes)._  
_Buena práctica de Check Point: ASG en ≥ 2 AZ con mínimo n+1, GWLB cross-zone, CME con plantilla y política, y comprobación de actualizaciones (THR-06) en cada gateway nuevo._

**Procedimiento:**

1. Corta temporalmente la conexión de los gateways con la gestión (regla de salida o NACL).
2. Ejecuta un lote corto del kit (NET-01, IPS-01, TLS-01) y verifica decisiones y que los registros se acumulan.
3. Restaura y comprueba que llegan los registros pendientes; repite cortando el DNS de los gateways.

**Resultado esperado:** Política aplicada sin gestión ni DNS; registros recuperados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### HA-08 · Recuperación ante desastre y restauración

**Prioridad:** Media · _Manual_  
**Objetivo:** Se puede reconstruir el despliegue completo desde código y copias.  
**Configuración necesaria en el firewall:** Infraestructura como código y copia de la gestión.  
_Notas de Check Point: Terraform de los módulos oficiales + política como código; Smart-1 Cloud con copias gestionadas por el servicio._  
_Buena práctica de Check Point: ASG en ≥ 2 AZ con mínimo n+1, GWLB cross-zone, CME con plantilla y política, y comprobación de actualizaciones (THR-06) en cada gateway nuevo._

**Procedimiento:**

1. Destruye el plano de inspección (o despliega en otra región) con el código de infraestructura.
2. Recrea, deja que la gestión aprovisione los gateways e instale la política.
3. Ejecuta el lote completo y mide el tiempo total (RTO).

**Resultado esperado:** Entorno recuperado y con los mismos resultados; RTO medido.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="perf"></a>
## PERF · Rendimiento y capacidad

### PERF-01 · Throughput con política L3/L4

**Prioridad:** Crítica  
**Objetivo:** Se mide el caudal a través del firewall solo con control de acceso.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: iperf3 al puerto de excepción (permitido entre entornos y excluido de la prevención de amenazas): subida y bajada con 4 flujos y un flujo único (límite por flujo)._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-01.1 | Subida TCP, 4 flujos, 20 s (solo desde el papel `perf_client`) | Caudal agregado del cliente al servidor. | Medida | Performance |
| PERF-01.2 | Bajada TCP, 4 flujos, 20 s (solo desde el papel `perf_client`) | Servidor → cliente (-R). | Medida | Performance |
| PERF-01.3 | Flujo TCP único, 20 s (solo desde el papel `perf_client`) | Un flujo va siempre al mismo gateway y núcleo: límite por flujo. | Medida | Performance |

### PERF-02 · Throughput con IPS y protección avanzada

**Prioridad:** Crítica  
**Objetivo:** Se mide el caudal con todas las capacidades de inspección activas.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: Descargas paralelas de un fichero de 200 MB por HTTP (IPS, anti-malware, DLP) y por HTTPS descifrado y sin descifrar, desde el servidor de pruebas._  
_Buena práctica de Check Point: Medir con el perfil que se va a usar en producción; con TLS, dimensionar por la cifra descifrada._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-02.1 | HTTP inspeccionado, 4 descargas en paralelo (solo desde el papel `perf_client`) | Perfil completo de amenazas. | Medida | Performance / IPS / Anti-malware |
| PERF-02.2 | HTTPS descifrado, 4 descargas en paralelo (solo desde el papel `perf_client`) | Inspección TLS más perfil completo. | Medida | Performance / TLS inspection |
| PERF-02.3 | HTTPS sin descifrar, 4 descargas en paralelo (solo desde el papel `perf_client`) | Referencia sin descifrado. | Medida | Performance / TLS inspection (bypass) |

### PERF-03 · Latencia y jitter p50/p95/p99

**Prioridad:** Crítica  
**Objetivo:** Se mide la latencia que añade el camino de inspección.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: 200 muestras de eco ICMP, de establecimiento TCP y de petición HTTP completa al servidor de pruebas._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-03.1 | ICMP (200 ecos) (solo desde el papel `perf_client`) | Ida y vuelta de red. | Medida | Performance |
| PERF-03.2 | Establecimiento TCP (200) (solo desde el papel `perf_client`) | Incluye la decisión del firewall para cada conexión nueva. | Medida | Performance |
| PERF-03.3 | Petición HTTP completa (200) (solo desde el papel `perf_client`) | Incluye la inspección del contenido. | Medida | Performance |

### PERF-04 · Conexiones simultáneas

**Prioridad:** Alta  
**Objetivo:** El firewall mantiene muchas sesiones abiertas a la vez.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: 2000 sesiones TCP abiertas a la vez desde un cliente, cada una usada, mantenida 30 s y usada otra vez._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-04.1 | 2000 sesiones simultáneas (solo desde el papel `perf_client`) | Capacidad de la tabla de estado (limitada por un único cliente). | Medida | Performance |

### PERF-05 · Conexiones nuevas por segundo (CPS)

**Prioridad:** Alta  
**Objetivo:** Se mide la tasa de conexiones nuevas que procesa el firewall.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: Peticiones HTTP cortas (conectar, GET, cerrar) con 64 en paralelo durante 20 s._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-05.1 | CPS sostenido 20 s (solo desde el papel `perf_client`) | Medido desde un cliente: es un mínimo, no el máximo del firewall. | Medida | Performance |

### PERF-06 · Ráfagas y carga sostenida

**Prioridad:** Alta  
**Objetivo:** El caudal se mantiene estable con carga continua y absorbe ráfagas.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: iperf3 sostenido 120 s (mínimo, media y máximo por segundo, retransmisiones), ráfaga de 16 flujos y ráfaga de conexiones nuevas._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-06.1 | Carga sostenida 120 s (solo desde el papel `perf_client`) | Estabilidad segundo a segundo. | Medida | Performance |
| PERF-06.2 | Ráfaga de 16 flujos, 15 s (solo desde el papel `perf_client`) | Reparto entre gateways y núcleos. | Medida | Performance |
| PERF-06.3 | Ráfaga de conexiones (256 en paralelo, 10 s) (solo desde el papel `perf_client`) | Pico de conexiones nuevas. | Medida | Performance |

### PERF-07 · Tamaño de paquete y TCP/UDP

**Prioridad:** Alta  
**Objetivo:** Se documenta el rendimiento con paquetes pequeños y grandes en TCP y UDP.  
**Configuración necesaria en el firewall:** Papel «perf_client»: un cliente lanza las medidas (el servidor iperf3 atiende una prueba a la vez). Puerto de excepción (iperf3 TCP/UDP) permitido entre entornos y sin inspección de amenazas.  
_Notas de Check Point: iperf3 UDP a 300 Mbit/s con datagramas de 64, 512 y 1400 bytes (paquetes por segundo, pérdida, jitter) y TCP con MSS de 536 bytes._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-07.1 | UDP 64 bytes (solo desde el papel `perf_client`) | Paquetes pequeños: límite en paquetes por segundo. | Medida | Performance |
| PERF-07.2 | UDP 512 bytes (solo desde el papel `perf_client`) | Tamaño medio. | Medida | Performance |
| PERF-07.3 | UDP 1400 bytes (solo desde el papel `perf_client`) | Cerca de la MTU (con GENEVE). | Medida | Performance |
| PERF-07.4 | TCP con MSS 536 (solo desde el papel `perf_client`) | Segmentos TCP pequeños. | Medida | Performance |

### PERF-08 · Consumo de recursos y coste por carga

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Se relaciona la carga con el consumo de los gateways y su coste.  
**Configuración necesaria en el firewall:** Agente de control en marcha con credenciales de la nube (lectura; las pruebas de HA cambian el grupo de autoescalado y las ACL de red) y de la API de gestión.  
_Notas de Check Point: El agente de control lanza carga desde el cliente de rendimiento (iperf3 y descargas HTTP inspeccionadas) mientras muestrea la CPU de los gateways cada 5 s y en CloudWatch, y calcula el coste de cómputo por hora con la API de precios._  
_Buena práctica de Check Point: Dimensionar con el perfil real; instancias de cómputo optimizado; SecureXL/CoreXL y Dynamic Balancing activos; escalar por CPU._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| PERF-08.1 | CPU y coste bajo carga | Medida combinada de carga, CPU y coste. | Medida | Performance / Cost |

<a id="ops"></a>
## OPS · Operación y gobierno

### OPS-01 · Onboarding automatizado y mínimo privilegio

**Prioridad:** Alta · _agente de control_  
**Objetivo:** La gestión lee la cuenta con un rol de solo lectura y acotado.  
**Configuración necesaria en el firewall:** aws.cme_role_arn configurado en el agente de control.  
_Notas de Check Point: Se analiza el rol que usa la gestión (CME) para descubrir el grupo de autoescalado: acciones permitidas, comodines, principal de confianza y ExternalId._  
_Buena práctica de Check Point: Rol STS de solo lectura con ExternalId para CME/CloudGuard Controller; sin claves de acceso de larga duración._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| OPS-01.1 | Permisos del rol de la gestión | Sin comodines ni escrituras, con ExternalId. | Cumple criterio | Operations |

### OPS-02 · Administración RBAC/SSO/MFA

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Los administradores entran con SSO y MFA y con permisos mínimos por perfil.  
**Configuración necesaria en el firewall:** Proveedor de identidad corporativo (SAML/OIDC).  
_Notas de Check Point: Infinity Portal con SSO (SAML) y MFA; perfiles de permisos por capa y por dominio._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Integra el portal/gestión con el IdP corporativo por SAML y exige MFA.
2. Crea un perfil de solo lectura y otro de operador de políticas; prueba que cada uno solo puede lo suyo.
3. Verifica en auditoría el usuario real de cada acción.

**Resultado esperado:** SSO+MFA obligatorios y permisos separados verificados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-03 · Políticas por API, Terraform y CI/CD

**Prioridad:** Alta · _agente de control_  
**Objetivo:** Un cambio de política hecho por API se aplica de extremo a extremo y se revierte.  
**Configuración necesaria en el firewall:** Acceso de escritura a la API de gestión (solo objetos TK_ y gateways de prueba).  
_Notas de Check Point: Se añade por API una regla temporal que bloquea http de un cliente al servidor, se publica e instala, se mide cuándo se bloquea el tráfico, se elimina, se reinstala y se mide cuándo vuelve._  
_Buena práctica de Check Point: Terraform provider de Check Point o API con publicación e instalación en el pipeline y revisión por pares._

| ID | Prueba | Qué hace | Esperado | Capacidad |
|---|---|---|---|---|
| OPS-03.1 | Cambio y reversión por API medidos | Instala la política de acceso dos veces en los gateways de prueba. | Cumple criterio | Operations |

### OPS-04 · Gestión centralizada multi-cuenta/tenant

**Prioridad:** Alta · _Manual_  
**Objetivo:** Una consola gestiona varias cuentas y entornos con separación.  
**Configuración necesaria en el firewall:** Al menos dos cuentas o entornos.  
_Notas de Check Point: CME con varias cuentas/plantillas; Multi-Domain en Smart-1 Cloud si se necesita separación por tenant._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Registra varias cuentas en el conector de autoescalado/nube.
2. Asigna paquetes de política o dominios distintos y comprueba que un administrador de uno no ve el otro.

**Resultado esperado:** Gestión central con separación verificada.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-05 · Versiones, copia y vuelta atrás

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se puede volver a una versión anterior de política o de software.  
**Configuración necesaria en el firewall:** Historial de revisiones de política.  
_Notas de Check Point: Installation History → «Install specific version»; las revisiones se conservan automáticamente._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Publica e instala un cambio y luego vuelve a la revisión anterior desde el historial.
2. Verifica con el kit que el comportamiento vuelve al anterior.

**Resultado esperado:** Vuelta atrás completa en minutos y verificada.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-06 · Experiencia operativa en alta/baja/modificación de reglas

**Prioridad:** Alta · _Manual_  
**Objetivo:** Las tareas habituales son rápidas y con poco riesgo de error.  
**Configuración necesaria en el firewall:** Operadores del cliente con acceso a la consola.  
_Notas de Check Point: Sesiones con vista de cambios, búsqueda de objetos en uso («Where used») y secciones en las capas (como las que crea el kit)._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Un operador del cliente da de alta, modifica y elimina una regla con la consola, cronometrando cada tarea.
2. Comprueba las validaciones (conflictos, objetos duplicados) y la vista previa de cambios antes de publicar.

**Resultado esperado:** Tiempos y valoración de los operadores documentados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-07 · Gobierno de excepciones y trazabilidad ITSM

**Prioridad:** Crítica · _Manual_  
**Objetivo:** Cada excepción se vincula a un ticket y se revisa periódicamente.  
**Configuración necesaria en el firewall:** Herramienta ITSM corporativa.  
_Notas de Check Point: Campo de ticket en la sesión/regla, integración ITSM por API y caducidad con objetos de tiempo._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Crea una excepción indicando el número de ticket en el comentario/sesión.
2. Comprueba que desde el ticket se llega a la regla y viceversa.
3. Lista las excepciones caducadas o sin ticket.

**Resultado esperado:** Todas las excepciones trazables y revisables.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-08 · Etiquetado, descubrimiento continuo y alta de políticas

**Prioridad:** Alta · _Manual_  
**Objetivo:** Los activos nuevos se descubren y reciben política según su etiqueta.  
**Configuración necesaria en el firewall:** Convención de etiquetas (entorno, aplicación, criticidad).  
_Notas de Check Point: CloudGuard Controller + regla de limpieza en Drop con registro._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Define la convención de etiquetas y crea objetos dinámicos para cada valor.
2. Despliega un activo nuevo etiquetado y comprueba que recibe la política esperada (ver POL-08).
3. Detecta activos sin etiqueta y su tratamiento por defecto (denegación).

**Resultado esperado:** Alta automática por etiqueta; activos sin etiqueta denegados.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### OPS-09 · Control de credenciales y secretos de gestión

**Prioridad:** Alta · _Manual_  
**Objetivo:** Las credenciales de gestión y automatización están protegidas y rotadas.  
**Configuración necesaria en el firewall:** Gestor de secretos corporativo.  
_Notas de Check Point: Una clave API por integración con permisos mínimos; roles STS (sin claves de larga duración) para el conector de nube._  
_Buena práctica de Check Point: Smart-1 Cloud con SSO+MFA, política como código y claves API por automatización con permisos mínimos._

**Procedimiento:**

1. Inventaria claves API, credenciales de nube y claves SIC/aprovisionamiento.
2. Comprueba que se guardan en un gestor de secretos, sin texto plano en código ni repositorios.
3. Rota una clave API y verifica que la automatización sigue funcionando.

**Resultado esperado:** Sin secretos en claro y rotación probada.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="int"></a>
## INT · Integraciones

### INT-01 · Integración con Entra ID para acceso administrativo

**Prioridad:** Media · _Manual_  
**Objetivo:** Los administradores se autentican con Entra ID.  
**Configuración necesaria en el firewall:** Inquilino de Entra ID con aplicación empresarial SAML.  
_Notas de Check Point: Infinity Portal → Identity providers → Entra ID (SAML)._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Crea la aplicación SAML en Entra ID y configúrala como IdP del portal de gestión.
2. Asigna grupos a perfiles de permisos y prueba el acceso con MFA condicional.

**Resultado esperado:** Acceso con Entra ID y perfiles por grupo.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### INT-02 · Integración PingID/PingOne para administradores

**Prioridad:** Media · _Manual_  
**Objetivo:** Los administradores se autentican con PingOne.  
**Configuración necesaria en el firewall:** Entorno PingOne con aplicación SAML.  
_Notas de Check Point: Infinity Portal admite cualquier IdP SAML 2.0._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Configura PingOne como IdP SAML del portal de gestión.
2. Prueba el acceso con MFA de PingID y el mapeo de grupos.

**Resultado esperado:** Acceso con PingOne y MFA.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### INT-03 · Alertas y casos hacia ServiceNow

**Prioridad:** Media · _Manual_  
**Objetivo:** Los eventos críticos abren casos en el ITSM.  
**Configuración necesaria en el firewall:** Instancia ITSM con API.  
_Notas de Check Point: Infinity Events / Playblocks con acciones hacia ServiceNow._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Configura la integración de eventos → ITSM (webhook o conector).
2. Ejecuta IPS-01 y comprueba que se abre un caso con los datos del evento.

**Resultado esperado:** Caso creado automáticamente con contexto.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### INT-04 · Interoperabilidad con herramientas SOC

**Prioridad:** Alta · _Manual_  
**Objetivo:** El SOC consume eventos y puede actuar (bloquear) desde sus herramientas.  
**Configuración necesaria en el firewall:** SIEM/SOAR del SOC.  
_Notas de Check Point: API de gestión (indicadores, objetos dinámicos), Log Exporter y conectores SOAR._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Envía eventos al SIEM (OBS-04).
2. Desde el SOAR, añade un indicador por API (como IPS-10) y verifica el bloqueo.

**Resultado esperado:** Ciclo detectar → bloquear automatizado.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### INT-05 · Contenedores/Kubernetes y servicios dinámicos

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** La política sigue a cargas dinámicas (pods, servicios).  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita un clúster EKS en un spoke.  
_Notas de Check Point: CloudGuard Controller para Kubernetes y CloudGuard CNAPP para seguridad dentro del clúster._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Despliega un clúster con servicios etiquetados en un spoke.
2. Usa objetos dinámicos por namespace/etiqueta en la política y escala los pods.
3. Verifica que las reglas siguen a los pods.

**Resultado esperado:** Política aplicada a cargas dinámicas sin tocar reglas.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### INT-06 · Mismo control en varias regiones o nubes

**Prioridad:** Media · _Manual_ · _requiere infraestructura adicional_  
**Objetivo:** Una política común se aplica en varias regiones o nubes.  
**Configuración necesaria en el firewall:** Fuera del laboratorio de referencia: necesita una segunda región o nube.  
_Notas de Check Point: Una gestión y una política compartida; plantillas CME por región._  
_Buena práctica de Check Point: IdP SAML en Infinity Portal y API de gestión para SOAR/ITSM._

**Procedimiento:**

1. Despliega el mismo patrón en otra región/nube con el mismo código.
2. Instala la misma política y ejecuta el lote del kit en ambas.
3. Compara los resultados con el informe comparativo del portal.

**Resultado esperado:** Mismos resultados en ambas ubicaciones.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

<a id="cost"></a>
## COST · Coste y eficiencia

### COST-01 · Coste fijo de plataforma y licencias

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se conoce el coste fijo mensual de la solución.  
**Configuración necesaria en el firewall:** Precios de licencia y de la gestión.  
_Notas de Check Point: Licenciamiento por vCPU o PAYG en Marketplace; Smart-1 Cloud como servicio._  
_Buena práctica de Check Point: PAYG para picos y BYOL para la base; bypass TLS de tráfico de confianza de alto volumen para ahorrar CPU._

**Procedimiento:**

1. Suma licencias (BYOL/PAYG), gestión y soporte para el tamaño mínimo (2 gateways en 2 AZ).
2. Añade el coste fijo de AWS: instancias, GWLB, endpoints y attachments del TGW por hora.

**Resultado esperado:** Coste fijo mensual desglosado.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### COST-02 · Coste variable por GB y rutas AWS

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se conoce el coste por GB inspeccionado según el camino.  
**Configuración necesaria en el firewall:** Volúmenes de tráfico estimados.  
_Notas de Check Point: Calculadora de AWS + consumo real (Cost Explorer por etiqueta) del laboratorio durante la POC._  
_Buena práctica de Check Point: PAYG para picos y BYOL para la base; bypass TLS de tráfico de confianza de alto volumen para ahorrar CPU._

**Procedimiento:**

1. Para este-oeste y salida, suma procesamiento de TGW, GWLB endpoint, GWLB, NAT y transferencia entre AZ por GB.
2. Contrasta con el consumo real tras una ejecución de PERF.

**Resultado esperado:** Coste por GB por camino.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### COST-03 · Coste incremental de IPS/TLS/AV

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se estima el coste de activar las capacidades avanzadas.  
**Configuración necesaria en el firewall:** Resultados de PERF-01, PERF-02 y PERF-08.  
_Notas de Check Point: Dimensionar con el perfil real (Optimized/Strict) y bypass TLS de categorías sensibles y de alto volumen de confianza._  
_Buena práctica de Check Point: PAYG para picos y BYOL para la base; bypass TLS de tráfico de confianza de alto volumen para ahorrar CPU._

**Procedimiento:**

1. Compara el caudal y la CPU con política L3/L4 (PERF-01) y con perfil completo (PERF-02/PERF-08).
2. Traduce la diferencia en número de gateways (y coste) para el tráfico previsto.

**Resultado esperado:** Coste incremental justificado con medidas.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### COST-04 · Coste de redundancia AZ y escalado

**Prioridad:** Media · _Manual_  
**Objetivo:** Se conoce el coste de la alta disponibilidad y del escalado.  
**Configuración necesaria en el firewall:** Resultados de HA-02 y HA-05.  
_Notas de Check Point: Calculadora de AWS + consumo real (Cost Explorer por etiqueta) del laboratorio durante la POC._  
_Buena práctica de Check Point: PAYG para picos y BYOL para la base; bypass TLS de tráfico de confianza de alto volumen para ahorrar CPU._

**Procedimiento:**

1. Calcula el coste del mínimo redundante (n+1 por AZ) y de cada gateway adicional por escalado.
2. Usa los umbrales de escalado observados para estimar horas de escalado al mes.

**Resultado esperado:** Coste de HA y de picos documentado.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.

### COST-05 · Coste de administración, soporte y registros

**Prioridad:** Alta · _Manual_  
**Objetivo:** Se estima el esfuerzo operativo y el coste de registros.  
**Configuración necesaria en el firewall:** Volumen de registros de una ejecución completa.  
_Notas de Check Point: Retención incluida en Smart-1 Cloud según plan; registrar Accept solo donde aporta (secciones con registro selectivo)._  
_Buena práctica de Check Point: PAYG para picos y BYOL para la base; bypass TLS de tráfico de confianza de alto volumen para ahorrar CPU._

**Procedimiento:**

1. Mide los registros por día de una ejecución y extrapola al tráfico real.
2. Estima horas de operación al mes (OPS-06) y coste de retención/SIEM.

**Resultado esperado:** Coste operativo anual estimado.  
**Evidencias:** Capturas de la consola de gestión y de la nube con fecha y hora, exportación de registros y notas del procedimiento.
