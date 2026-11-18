###############################################################################
# Firewall Testkit lab: hub-and-spoke on AWS with centralized inspection by
# Check Point Cloud Firewall (TGW + GWLB + autoscaling group), managed by your
# Check Point management (e.g. Smart-1 Cloud) through CME.
#
#   spokes.tf      — one VPC + test VM per environment (var.environments)
#   inspection.tf  — inspection VPC: TGW attachment (appliance mode) + GWLB endpoints
#   egress.tf      — egress VPC: NAT Gateway per AZ (centralized Internet egress)
#   public.tf      — firewall VPC: GWLB + Check Point Cloud Firewall autoscaling group
#   tgw.tf         — Transit Gateway and route tables
#   cme_iam.tf     — STS access for CME (read-only role with external ID)
###############################################################################

locals {
  p   = var.name_prefix
  azs = ["${var.region}a", "${var.region}b"]

  # Per environment (/16 recommended): workload /26 at .0 (AZ a) and .64 (AZ b), TGW /28 at .128 and .144,
  # lab management /24 at x.x.255.0
  spokes = {
    for name, e in var.environments : name => {
      cidr     = e.cidr
      vm_az    = "${var.region}${e.az}"
      tgw      = { (local.azs[0]) = cidrsubnet(e.cidr, 12, 8), (local.azs[1]) = cidrsubnet(e.cidr, 12, 9) }
      workload = { (local.azs[0]) = cidrsubnet(e.cidr, 10, 0), (local.azs[1]) = cidrsubnet(e.cidr, 10, 1) }
    }
  }

  inspection = {
    cidr     = var.inspection_cidr
    tgw      = { (local.azs[0]) = cidrsubnet(var.inspection_cidr, 12, 8), (local.azs[1]) = cidrsubnet(var.inspection_cidr, 12, 9) }
    firewall = { (local.azs[0]) = cidrsubnet(var.inspection_cidr, 12, 10), (local.azs[1]) = cidrsubnet(var.inspection_cidr, 12, 11) }
  }

  egress = {
    cidr = var.egress_cidr
    tgw  = { (local.azs[0]) = cidrsubnet(var.egress_cidr, 12, 8), (local.azs[1]) = cidrsubnet(var.egress_cidr, 12, 9) }
    nat  = { (local.azs[0]) = cidrsubnet(var.egress_cidr, 12, 10), (local.azs[1]) = cidrsubnet(var.egress_cidr, 12, 11) }
  }

  public_cidr = var.firewall_cidr
}

resource "aws_key_pair" "lab" {
  key_name   = "${local.p}-lab"
  public_key = file(var.ssh_public_key_file)
}

resource "aws_ec2_transit_gateway" "this" {
  description                     = "${local.p} - environments + inspection + egress"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = { Name = "${local.p}-tgw" }
}
