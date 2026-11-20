# Configuración base de Check Point (opcional)

_English: [checkpoint-baseline.md](../en/checkpoint-baseline.md)_

`checkpoint/cp-baseline.sh` prepara una gestora de Check Point para una campaña de pruebas: crea un paquete de
política que sigue las best practices de Check Point e implementa exactamente lo que espera el kit según la
Configuración del portal.

## Requisitos

- Una gestora de Check Point accesible por la Management API (Smart-1 Cloud u on-premises R81.20+) y una API key de un
  administrador con permisos de lectura y escritura. Se recomienda una gestora dedicada a las pruebas: la herramienta
  también cambia ajustes globales de inspección TLS (validación del certificado del servidor y CA outbound si no hay).
- `curl`, `jq`, `openssl`.
- Cada entorno de la Configuración del portal necesita un **CIDR**.

## Uso

```bash
cd checkpoint
./cp-baseline.sh setup                                          # URL (…/web_api) + API key → settings.env
./cp-baseline.sh apply --portal http://<IP del servidor>/portal --push-ca
./cp-baseline.sh install <gateway> [<gateway> …]                # o: install --prefix <prefijo de los gateways>
./cp-baseline.sh remove [--gateways-prefix <prefijo>]           # borra el paquete y todos los objetos TK_
```

`apply` también admite un fichero (`--config fichero.json --testkit-ca ca.crt`) si el portal no es accesible. Con
`--push-ca` sube la CA de HTTPS Inspection a la Configuración del portal, para que los clientes confíen en ella y las
pruebas TLS sepan qué certificados se descifraron. Repetir `apply` es seguro: crea lo que falte y reordena las reglas.

Las capas de acceso y de HTTPS Inspection se agrupan en secciones (`TK · Data loss prevention`, `TK · Segmentation
exceptions`, `TK · Segmentation matrix`, `TK · Internet egress`, `TK · Cleanup`; en la capa de salida `TK · Geo-blocking`,
`TK · Applications and URL filtering`, `TK · Allowed web and DNS`; en HTTPS `TK · Bypass` y `TK · Inspect`). Las reglas de
Threat Prevention se ordenan pero sin secciones: la Management API no permite crearlas en esa capa.

## Qué configura

| Área | Configuración |
|---|---|
| Objetos | Redes `TK_<entorno>`, `TK_Envs`, `TK_Internal`, servicio del puerto de excepción y HTTP/HTTPS con firma de protocolo, sitios personalizados (FQDN y ruta bloqueados, bypass TLS), objetos actualizables GEO y de bypass recomendado |
| Acceso | DLP (tarjetas, IBAN, ejecutables; excepción DLP opcional), puerto de excepción entre entornos, una regla Accept por par permitido de la matriz, aislamiento, capa en línea de Internet, limpieza |
| Salida | Geobloqueo, aplicaciones bloqueadas (redes sociales, compartición de ficheros, SSH, DoH), categorías bloqueadas, aplicaciones de alto riesgo, sitios personalizados, HTTP/HTTPS con firma de protocolo + DNS |
| Prevención de amenazas | Perfiles por tipo de flujo (este-oeste, Internet, Detect), protecciones OT/SCADA desactivadas por tags en este-oeste, protección de tautologías SQL activada, excepción del puerto de excepción, excepción IPS por activo y regla IDS opcionales |
| Inspección TLS | CA outbound, CA del kit de confianza, capa HTTPS propia con bypass por FQDN/lista recomendada/categorías sensibles e Inspect este-oeste e Internet, validación del certificado del servidor |

Detalle y motivo de cada decisión: [configuracion-firewall.md](configuracion-firewall.md).
