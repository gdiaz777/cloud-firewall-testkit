###############################################################################
# Firewall VPC — GWLB + Check Point Cloud Firewall autoscaling group managed by
# your management through CME (CME finds the ASG by the x-chkp-template tag).
# Not attached to the TGW: the inspection VPC consumes the GWLB over PrivateLink.
# Gateways reach the management through their EIPs and this VPC's IGW.
###############################################################################

module "public_vpc" {
  source = "./modules/checkpoint/vpc"

  vpc_cidr            = local.public_cidr
  public_subnets_map  = { (local.azs[0]) = 1, (local.azs[1]) = 2 }
  private_subnets_map = {}
  tgw_subnets_map     = {}
  subnets_bit_length  = 10
}

resource "aws_ec2_tag" "public_vpc_name" {
  resource_id = module.public_vpc.vpc_id
  key         = "Name"
  value       = "${local.p}-public"
}

resource "aws_ec2_tag" "public_igw_name" {
  resource_id = module.public_vpc.aws_igw
  key         = "Name"
  value       = "${local.p}-public-igw"
}

module "cp_gwlb" {
  source = "./modules/checkpoint/gwlb"

  vpc_id     = module.public_vpc.vpc_id
  subnet_ids = module.public_vpc.public_subnets_ids_list

  key_name                 = aws_key_pair.lab.key_name
  admin_cidr               = var.admin_cidrs[0]
  gateways_addresses       = var.cp_gateways_addresses
  enable_volume_encryption = true
  metadata_imdsv2_required = true

  gateway_load_balancer_name       = "${local.p}-gwlb"
  target_group_name                = "${local.p}-tg"
  enable_cross_zone_load_balancing = true
  connection_acceptance_required   = false

  gateway_name                           = "${local.p}-cp-gw"
  gateway_instance_type                  = var.cp_gateway_instance_type
  gateway_version                        = var.cp_gateway_version
  gateway_SICKey                         = var.cp_gateway_sic_key
  gateway_password_hash                  = var.cp_gateway_password_hash
  gateway_maintenance_mode_password_hash = ""
  gateway_management                     = "Over the internet"
  # Default "early drop" is kept (sk111643): disabling it names the rule in the logs instead of
  # CPEarlyDrop but lets the TCP handshake of disallowed ports complete while the application is identified.
  gateway_bootstrap_script        = ""
  gateways_provision_address_type = "public"
  allocate_public_IP              = true
  minimum_group_size              = var.cp_min_group_size
  maximum_group_size              = var.cp_max_group_size
  enable_cloudwatch               = true
  configuration_template          = var.cp_configuration_template
  management_server               = var.cp_management_server

  # Gateway security group:
  #  - everything from the firewall VPC (GWLB health check tcp/8117 and GENEVE udp/6081)
  #  - from the Internet ONLY the Check Point management ports: with ip-address=public, CME sets up SIC and
  #    pushes the policy to the gateway EIP (without them new gateways never register)
  #  - unrestricted egress (management, ThreatCloud, updates)
  gateway_security_rules = [
    { direction = "ingress", from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = [local.public_cidr] },
    { direction = "ingress", from_port = 257, to_port = 257, protocol = "tcp", cidr_blocks = [var.cp_gateways_addresses] },
    { direction = "ingress", from_port = 18191, to_port = 18192, protocol = "tcp", cidr_blocks = [var.cp_gateways_addresses] },
    { direction = "ingress", from_port = 18211, to_port = 18211, protocol = "tcp", cidr_blocks = [var.cp_gateways_addresses] },
    { direction = "ingress", from_port = 18264, to_port = 18264, protocol = "tcp", cidr_blocks = [var.cp_gateways_addresses] },
    { direction = "egress", from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"] },
  ]

  # No management server is deployed in AWS; the module validates these fields anyway.
  management_deploy                         = false
  management_instance_type                  = "m5.xlarge"
  management_version                        = "R81.20-BYOL"
  management_password_hash                  = ""
  management_maintenance_mode_password_hash = ""
}
