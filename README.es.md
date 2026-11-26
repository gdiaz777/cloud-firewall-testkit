# Firewall Testkit

_English: [README.md](README.md)_

Kit portable y neutral respecto al fabricante para **validar y comparar soluciones de seguridad de red** (firewalls
cloud, NGFW, segmentación este-oeste e inspección de la salida) con pruebas repetibles y explicadas, un portal web e
informes Word en español e inglés.

Lanza un contenedor como **servidor de pruebas** y un contenedor **cliente** en cada segmento de red. Los clientes
apuntan al servidor, cada prueba atraviesa la solución de seguridad y el portal genera el informe, sea cual sea la
arquitectura.

![Portal – pruebas](docs/img/portal-tests-es.png)

## Qué prueba

**117 casos de prueba en 14 dominios**: arquitectura y enrutamiento, políticas y segmentación, prevención de
intrusiones, malware, **inspección TLS** (incluida la evasión sobre HTTPS), control de aplicaciones y URL, DLP,
cobertura de ataques web, visibilidad y auditoría, **alta disponibilidad**, **rendimiento**, operación,
integraciones y coste.

- **69 casos automáticos (222 comprobaciones)**: desde los clientes (tráfico a través de la solución) y, para alta
  disponibilidad, registros, política y operación, desde un **agente de control** opcional en un equipo de
  administración (API de la nube y de la gestión; provoca la caída de gateways mientras todos los clientes sondean).
- **48 casos manuales**: procedimiento guiado, resultado esperado y evidencias (consolas, integraciones, costes), en el
  portal y en el informe.

Solo se usan estímulos inocuos (EICAR, patrones de ataque contra un servidor no vulnerable, datos sintéticos). Ver el
[catálogo de pruebas](docs/es/catalogo-pruebas.md). Lo que debe tener configurado el firewall está en la pestaña
**Configuración del firewall** del portal y en cada caso (neutral; si la solución probada es Check Point se muestran
además sus buenas prácticas).

## Puesta en marcha

### Equipos y Docker

Un equipo Linux por entorno (cualquier distribución con Docker Engine; 2 vCPU / 4 GB bastan, algo más en el cliente de
rendimiento) y el servidor de pruebas, que puede compartir equipo con uno de los clientes. Cada equipo necesita salida
HTTPS a `ghcr.io` para descargar la imagen (y al repositorio de Docker durante la instalación). Instala Docker Engine:

```bash
# Ubuntu / Debian (repositorio de Docker; en Debian cambia "ubuntu" por "debian")
sudo apt-get update && sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# RHEL / Rocky / Alma (repositorio de Docker)
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io

# Amazon Linux 2023
sudo dnf install -y docker

# todos: arranque con el sistema y docker sin sudo para tu usuario (cierra la sesión y vuelve a entrar después)
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
docker version && docker pull ghcr.io/gdiaz777/cloud-firewall-testkit:latest
```

¿Sin acceso a `ghcr.io`? Descarga la imagen en un equipo que lo tenga, `docker save
ghcr.io/gdiaz777/cloud-firewall-testkit:latest | gzip > testkit.tar.gz`, copia el fichero y ejecuta
`gunzip -c testkit.tar.gz | docker load` en cada equipo.

El tráfico de prueba debe salir por la interfaz que inspecciona la solución. Con una sola interfaz no hay que hacer
nada. Con una interfaz de gestión y otra de workload, la ruta hacia los demás entornos (y hacia Internet, para las
pruebas de salida) desde la IP de workload debe usar la interfaz de workload; el cliente usa como origen la IP de la
interfaz por la que llega al servidor (fuérzala con `-e SRC_IP=<IP de workload>`).

### Contenedores

En el **servidor de pruebas**. `SERVER_IP` es la **IP de workload** del servidor (la que los
clientes alcanzan a través de la solución); ponla si el equipo tiene más de una interfaz (p. ej. una de gestión), si no
se usa la primera:

```bash
docker run -d --name testkit-server --restart unless-stopped --network host -e SERVER_IP=<IP de workload del servidor> -v testkit-data:/data \
  ghcr.io/gdiaz777/cloud-firewall-testkit:latest server
```

En cada **cliente** (uno por segmento o entorno). `TESTKIT_ENV` es el nombre de entorno que usará el portal (p. ej.
`pro`, `pre`, `dev`): sin él se usa el nombre del equipo, y renombrarlo después en el portal rompe la relación con el
cliente:

```bash
docker run -d --name testkit-client --restart unless-stopped --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e SERVER=<IP de workload del servidor> -e TESTKIT_ENV=<nombre del entorno> ghcr.io/gdiaz777/cloud-firewall-testkit:latest client
```

En cada equipo cliente **salvo el del servidor de pruebas**, arranca también el servidor sin portal: los demás entornos
lo usan como destino (par de otra AZ, destino IDS, alcance este-oeste entre entornos):

```bash
docker run -d --name testkit-target --restart unless-stopped --network host -e PORTAL=0 -e SERVER_IP=<IP de workload de este equipo> \
  -v testkit-data:/data ghcr.io/gdiaz777/cloud-firewall-testkit:latest server
```

Abre `http://<IP del servidor>/portal/` (desde un equipo de administración: la dirección que alcances) → **Configuración**:

1. **Solución probada**: nombre y fabricante (etiqueta ejecuciones e informes; con Check Point se muestran sus notas y
   buenas prácticas).
2. **Entornos**: *Añadir clientes conectados* y completa CIDR, AZ, el entorno que aloja el **servidor de pruebas** y los
   pares en otra AZ; después la **matriz de segmentación** (qué puede alcanzar cada entorno).
3. **Papeles**: qué entornos hacen cada papel (producción/no producción, destino IDS, excepciones, **perf_client** para
   las pruebas de rendimiento…). Deja vacío lo que no aplique: esas pruebas salen como *no aplica*.
4. **Destinos en Internet**: cámbialos solo si la política usa otros sitios.
5. **CA de inspección TLS**: pega el certificado de la CA con la que la solución re-firma el TLS inspeccionado (la
   configuración base de Check Point de abajo la sube sola).
6. Guarda. Después configura el firewall como indica la pestaña **Configuración del firewall** (o aplica la
   configuración base de Check Point), ve a **Pruebas** y pulsa **Ejecutar todo**, o ejecuta pruebas y casos sueltos.

Al terminar, descarga el **informe Word (ES/EN)** o el CSV. Requisitos: los clientes deben llegar al servidor por
HTTP (tcp/80) a través de la solución; el servidor genera su propia CA de pruebas y los clientes la descargan solos.

Por consola en un cliente (sin portal): `docker exec testkit-client fw-tests run IPS-01 TLS-05`.
Incluye un `docker-compose.yml` con ambos perfiles.

## Opcional: agente de control (HA, registros, política, operación)

Algunas pruebas no se pueden hacer desde un workload: terminar o aislar un gateway, escalar el grupo, leer los
registros del firewall o medir un cambio de política de extremo a extremo. Las ejecuta un **agente de control** en un
equipo de administración con credenciales de la nube y de la gestión, que aparece en el portal como un cliente más
(`CONTROL`). Sin él, esas pruebas salen como *no aplica*. Ver [docs/es/agente-control.md](docs/es/agente-control.md).

## Comparar soluciones

Cambia **Solución probada** en Configuración, repite el lote con los mismos clientes, marca dos o más ejecuciones en
el panel **Ejecuciones** y descarga el **informe comparativo**: resultado global y por dominio, veredicto por caso
para cada solución y la lista de comprobaciones en las que difieren. Los resultados salen de lo que observan los
clientes (reinicio, descarte, página de bloqueo, emisor del certificado) y no de los registros del fabricante, así que
se mide a todos con la misma vara.

| Configuración | Informe |
|---|---|
| ![Configuración](docs/img/portal-settings-es.png) | ![Informe](docs/img/report.png) |

## Opcional: configuración base de Check Point

[`checkpoint/`](checkpoint/) configura una gestora de Check Point (p. ej. Smart-1 Cloud) a partir de la configuración
del portal con una política que sigue las best practices de Check Point —matriz de segmentación, control de salida,
prevención de amenazas por tipo de flujo, DLP e inspección TLS— y sube la CA de inspección al portal:

```bash
cd checkpoint && ./cp-baseline.sh setup                       # URL de la gestora + API key
./cp-baseline.sh apply --portal http://<dirección del portal>/portal --push-ca
./cp-baseline.sh install <gateway> …                         # o --prefix <prefijo>
```

Ejecútalo después de guardar la configuración del portal (lee de ahí entornos, matriz y papeles), desde un equipo que
alcance la API de la gestión y el portal (`<dirección del portal>`: la que abres en el navegador).

Ver [docs/es/checkpoint-baseline.md](docs/es/checkpoint-baseline.md) y la [guía de configuración de Check Point](docs/es/configuracion-firewall.md).

## Cómo funciona

- **Servidor**: nginx en 80/443 con tres nombres TLS (`inspect.testkit.lab`, `nodecrypt.testkit.lab`,
  `mtls.testkit.lab`), contenido de prueba (variantes de EICAR, ficheros benignos, tarjetas e IBAN sintéticos, un
  ejecutable), servicios en puertos que deben bloquearse (22, 23, 3389, 8080), iperf3 y el portal.
- **Cliente**: agente que ejecuta las pruebas desde su IP y envía los resultados al portal (zlib+base64, para que las
  cargas de ataque no disparen el IPS). También funciona por consola.
- **Catálogo**: `catalog/catalog.py` → `tests.json`, bilingüe; las notas específicas de Check Point van aparte y solo
  se muestran si la solución probada es Check Point.

Construcción local: `./build.sh` (imagen `cloud-firewall-testkit:local`).

## Seguridad

Úsalo solo en redes que estés autorizado a probar. Todos los estímulos son inocuos y todos los datos, sintéticos.

## Licencia

MIT: ver [LICENSE](LICENSE). No es un producto oficial de Check Point.
