# Desplegar un laboratorio completo

_English: [deploy.md](../en/deploy.md)_

`deploy/` construye desde cero un laboratorio de pruebas en una cuenta de AWS dedicada y configura tu gestora de Check
Point: infraestructura, CME, política, HTTPS Inspection, best practices, gateways, el kit y el portal. Después lanzas
las pruebas desde el portal o con un comando.

## Requisitos

- **Una gestora de Check Point** accesible por la Management API con **CME** (p. ej. un tenant de Smart-1 Cloud) y
  una **API key** con permisos de lectura y escritura. Usa una gestora dedicada al laboratorio: el kit crea su propio
  paquete de política y cambia ajustes globales de HTTPS Inspection (validación del certificado del servidor y CA
  outbound si no existe).
- **Una cuenta de AWS** dedicada y credenciales de administrador (variables de entorno o perfil). El laboratorio por
  defecto cuesta aproximadamente 2 gateways c5n.xlarge PAYG + 4 VM pequeñas + GWLB/TGW/NAT por hora.
- Herramientas locales: `terraform` ≥ 1.5, `jq`, `curl`, `openssl`, `ssh`.
- Aceptar en AWS Marketplace los términos de la AMI PAYG de Check Point Cloud Firewall (CloudGuard Network Security) en esa cuenta.

## Pasos

```bash
./deploy/setup.sh            # pide la URL de la web API y la API key de la gestora, perfil/región de AWS, prefijo y tamaño
vi deploy/state/lab.json     # opcional: entornos, matriz de segmentación, papeles, destinos en Internet
./deploy/up.sh --run         # lo construye todo (~30–40 min) y ejecuta el lote completo
./deploy/run.sh              # volver a ejecutar; informes en reports/<id>/
./deploy/down.sh             # destruir (con --purge-policy borra también el paquete y los objetos del kit)
```

`up.sh --from N` reanuda en un paso (1 comprobaciones, 2 certificados, 3 política, 4 Terraform, 5 CME, 6 gateways, 7 kit).

## Qué se crea

| Dónde | Objetos |
|---|---|
| Gestora | Paquete (por defecto `FW_Testkit`) con capa de acceso, capa en línea de salida `TK Egress Internet`, perfiles `TK_EastWest` / `TK_Strict` / `TK_Detect`, capa HTTPS `TK HTTPS Outbound`, redes `TK_<entorno>`, grupo `TK_Envs`, servicios y sitios `TK_*`, objetos actualizables GEO y de bypass, la CA del kit como CA de confianza y una CA de inspección outbound (si no hay) |
| CME | Cuenta AWS `<prefijo>-aws` (rol STS de solo lectura con external ID) y plantilla `<prefijo>-tpl` con HTTPS Inspection |
| AWS | Una VPC y una VM de prueba por entorno, VPC de inspección (GWLB endpoints, appliance mode), VPC de salida (NAT GW por AZ), VPC del firewall (GWLB + grupo de autoescalado), Transit Gateway con tablas spokes/inspection, usuario/rol IAM para CME |

## lab.json

Único fichero de diseño. `environments` (nombre, CIDR /16, AZ a|b) alimenta Terraform; `segmentation.allow` se
convierte en una regla Accept por par; `roles` colocan la regla IDS (Detect) y las excepciones IPS y DLP; `internet`
define los sitios personalizados y los objetos GEO. El mismo fichero (más las IP de las VM) se carga en la
Configuración del portal, así que política y resultados esperados siempre coinciden.

## Notas

- Prefijo ≤ 10 caracteres (con él se forma el nombre del GWLB).
- Los gateways tardan 10–20 minutos tras Terraform en darse de alta por CME; `gateways.sh` espera hasta 40 minutos.
- Los secretos quedan en local: `deploy/settings.env`, `deploy/.ssh/`, `certs/` y el estado de Terraform están en .gitignore.
- Los módulos de Terraform de `deploy/terraform/modules/checkpoint` proceden de CheckPointSW (Apache-2.0), con los
  cambios indicados en su NOTICE.md.
