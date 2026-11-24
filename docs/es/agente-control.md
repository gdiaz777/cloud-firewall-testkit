# Agente de control

_English: [control-agent.md](../en/control-agent.md)_

El agente de control ejecuta las pruebas **del lado del operador** del catálogo (marcadas *agente de control* en el
portal): alta disponibilidad (HA-01…05), registros y salud (OBS-01/02/08), auditoría de rutas (NET-06), higiene y
deriva de la política (POL-14/16), firmas e inteligencia de amenazas (IPS-03, THR-06), reacción a IoC (IPS-10),
recursos bajo carga (PERF-08) y operación (OPS-01/03).

Se ejecuta en un **equipo de administración** (nunca en un workload) con credenciales de la nube y de la gestión,
consulta el portal como cualquier cliente y aparece como `CONTROL`. Mientras provoca la caída de un gateway pide a
todos los clientes **sondas continuas** (servidor, Internet y un flujo denegado, una por segundo) y **sesiones
largas**, y mide las interrupciones.

## Puesta en marcha

```bash
git clone https://github.com/gdiaz777/cloud-firewall-testkit && cd cloud-firewall-testkit
pip install boto3            # hooks de AWS
export PORTAL_URL=http://<servidor>/portal CONTROL_CONFIG=control.json MGMT_API_KEY=<clave API de la gestión>
python3 control/agent.py                 # modo agente («Ejecutar todo» en el portal incluye sus pruebas)
python3 control/agent.py run HA-01       # puntual desde la línea de comandos
```

El fichero `control.json` tiene el mismo formato que en la [versión en inglés](../en/control-agent.md#run-it).

Nube y fabricante: hooks de AWS (`control/aws_hooks.py`) y de Check Point (`checkpoint/control_hooks.py`). Con otras
nubes o fabricantes esas pruebas salen como *no aplica*; un fabricante nuevo solo necesita un
`<fabricante>/control_hooks.py` que registre los hooks `fw.*`.

## Qué cambia y cómo lo deshace

| Prueba | Cambio | Vuelta atrás |
|---|---|---|
| HA-01 | termina un gateway del grupo de autoescalado | el grupo lanza un sustituto (se mide) |
| HA-02/04 | entradas de denegación en la ACL de red (/32) y un security group vacío en los gateways de una AZ, con los procesos de salud del ASG suspendidos | se eliminan las entradas, se restauran los security groups y se reanudan los procesos (en `finally`) |
| HA-03 | lo mismo para todos los gateways (todo el plano de inspección) | igual |
| HA-05 | capacidad deseada +1 (gateways existentes protegidos frente a la reducción) | vuelta a la capacidad inicial y protección retirada |
| IPS-10 | indicador de amenaza + instalación de la política de amenazas en los gateways de prueba | se borra el indicador y se reinstala |
| OPS-03 | regla temporal y dos objetos host + instalación de la política de acceso | se borran y se reinstala |
| POL-16 | una regla deshabilitada publicada (sin instalar) | se borra y se publica |
| PERF-08 | carga desde el cliente de rendimiento | — |

Las pruebas que cortan tráfico (marcadas como disruptivas) esperan a que terminen todos los clientes de la ejecución.
Las instalaciones de política y run-script solo afectan a los gateways de `mgmt.gateway_prefix`.

## Permisos

- **AWS** (equipo de control): `autoscaling:Describe*`, `SuspendProcesses`, `ResumeProcesses`, `TerminateInstanceInAutoScalingGroup`,
  `SetDesiredCapacity`, `SetInstanceProtection`, `UpdateAutoScalingGroup`; `ec2:Describe*`, `CreateNetworkAclEntry`,
  `DeleteNetworkAclEntry`, `CreateSecurityGroup`, `RevokeSecurityGroupEgress`, `DeleteSecurityGroup`, `ModifyNetworkInterfaceAttribute`; `elasticloadbalancing:Describe*`; `cloudwatch:GetMetricStatistics`, `DescribeAlarms`;
  `iam:GetRole*`, `ListRolePolicies`, `ListAttachedRolePolicies`, `GetPolicy*`; `pricing:GetProducts`.
- **Gestión**: una clave API cuyo perfil pueda leer, publicar, instalar política y ejecutar scripts en los gateways de prueba.
