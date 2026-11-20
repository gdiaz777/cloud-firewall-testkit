# Guía de configuración de Check Point

_English: [firewall-setup.md](../en/firewall-setup.md)_

El kit prueba lo que la política debe hacer. Esta página recoge la configuración de Check Point Cloud Firewall que
asume el catálogo, para que los resultados reflejen la política y no un requisito que falta. Los nombres son ejemplos.

## 1. Objetos y segmentación

1. Un objeto de red por entorno (por CIDR) y un grupo con todos.
2. Reglas que implementan la **matriz de segmentación** que introduces en la Configuración del portal (el kit espera
   exactamente esa matriz), una regla que permite HTTP/HTTPS/ICMP al entorno del servidor de pruebas y una regla
   final de limpieza **Drop + Log**.
3. Opcional: regla de excepción para un único puerto entre entornos (por defecto iperf3 tcp/5201, POL-02/POL-10),
   por encima de las de segmentación.

## 2. Salida a Internet (capa en línea)

| Regla | Contenido | Casos |
|---|---|---|
| Geobloqueo | Destino: objetos actualizables GEO de los países bloqueados | IPS-08 |
| Aplicaciones | Facebook, TikTok, Dropbox, WeTransfer, OpenSSH, SSH tunnelled, DoH → Drop | APP-01/02/04 |
| Categorías | Gambling, Anonymizer, Phishing, Hacking, Botnets… → Drop (no mezclar categorías y aplicaciones en la misma regla, sk112214) | APP-02 |
| Sitios personalizados | FQDN bloqueado (`www.example.org`) y ruta bloqueada (`www.example.com/testkit-blocked`) → Drop | POL-05, APP-03 |
| Permitir | Servicios HTTP/HTTPS con **match by protocol signature** + DNS → Accept | NET-03, APP-01 |
| Limpieza | Drop + Log | NET-03, APP-07 |

## 3. Threat Prevention

| Regla | Perfil | Notas |
|---|---|---|
| Entornos → destino IDS (opcional) | Perfil en Detect | IPS-11, POL-15 |
| Este-oeste entre entornos | IPS + Anti-Virus en Prevent | Excepciones: puerto de excepción (inactivo) y, opcional, IPS-04 |
| Entornos → Internet | IPS + Anti-Bot + Anti-Virus en Prevent | |

- Anti-Virus: inspeccionar ficheros en ambos sentidos en todas las interfaces y analizar comprimidos (los gateways
  detrás de GWLB tienen una sola interfaz).
- Excepción IPS-04 (opcional): protección *TP-Link Archer AX21 Command Injection (CVE-2023-1389)*, origen = entorno
  del papel `ips_exception_client`, destino = servidor, acción **Detect**.
- La familia de tautologías SQL («SQL Servers Blind SQL Injection Techniques») viene inactiva (impacto Critical);
  aun activándola, las tautologías en cuerpos urlencoded/JSON son un caso de WAF (WAF-01, informativa).

## 4. Content Awareness

- Reglas entre entornos sobre **HTTP y HTTPS**: tipos de datos *PCI – Credit Card Numbers* e *IBAN* → Drop; tipo de
  fichero *Executable* → Drop.
- Excepción DLP-02 opcional por encima: origen = papel `dlp_exception_client`, destino = servidor, dirección **up**, Accept.

## 5. HTTPS Inspection

1. Crear (o importar) el **certificado de inspección outbound** y pegar su parte pública en Configuración del portal → CA de inspección TLS
   (los clientes confían en ella; en producción, distribuirla por GPO/MDM).
2. Añadir la CA del kit (`http://<servidor>/portal/api/bootstrap`, campo `testkit_ca`) como **CA de confianza**, para que el gateway valide el servidor de pruebas al
   descifrar el HTTPS este-oeste.
3. Reglas de la capa HTTPS, en este orden:
   - Bypass: sitio personalizado con `nodecrypt.testkit.lab` y `mtls.testkit.lab` (TLS-04/05).
   - Bypass: objeto actualizable *HTTPS services – recommended bypass* (sk163595).
   - Bypass: categorías Financial Services, Health, Government/Military (privacidad).
   - Inspect: entornos → entornos.
   - Inspect: entornos → Internet.
   Detrás de un GWLB todo el tráfico entra por una sola interfaz: usa «no redes internas» (objeto negado) en lugar
   del objeto *Internet* en los destinos.
4. Advanced settings → validación del certificado del servidor: **bloquear no confiables, caducados y revocados** (TLS-03).
5. Activar HTTPS Inspection en los gateways (p. ej. en la plantilla de CME para grupos de autoescalado y en los existentes).
6. Mantener QUIC (UDP/443) bloqueado para que los navegadores vuelvan a TCP inspeccionado (TLS-06).

## 6. Buenas prácticas aplicadas

- Construir la política desde una **matriz de confianza** entre zonas; una regla y un perfil de Threat Prevention
  por tipo de flujo.
- Desactivar por **tags** las protecciones que no aplican (p. ej. fabricantes OT/SCADA en VPC solo IT) en vez de
  desactivarlas globalmente.
- Desplegar los perfiles nuevos primero en **Detect** (≥ 1 semana de aprendizaje y después Prevent), con las
  protecciones nuevas en staging.
- Preferir excepciones acotadas a protección + activo frente a cambios globales.
- Registrar todas las reglas; captura de paquetes en las reglas de Threat Prevention.

Referencias: sk108202 (best practices de HTTPS Inspection), sk163595 (lista de bypass), sk112214, sk159872,
sk112249 (best practices de App Control), sk95193 (ATRG: IPS).
