# Third-party code

This directory contains modules from **CheckPointSW/terraform-aws-cloudguard-network-security**
(https://github.com/CheckPointSW/terraform-aws-cloudguard-network-security), licensed under the
Apache License 2.0 (see LICENSE in this directory).

Modifications for Firewall Testkit (marked "Testkit patch" in the code):

- `gwlb`: passes `gateway_security_rules` to the gateway security group (upstream leaves it open).
- `autoscale_gwlb`: termination policy `NewestInstance`; scale-out at CPU > 60 % for 3 min adding 2 gateways
  (cooldown 600 s); scale-in at CPU < 30 % for 4 × 5 min removing 1 gateway (cooldown 900 s).
