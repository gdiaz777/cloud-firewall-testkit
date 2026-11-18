###############################################################################
# One VPC per environment with a test VM (Docker: testkit server + client).
# Place VMs in different AZs to cover same-AZ and cross-AZ flows.
###############################################################################

module "spoke" {
  source   = "./modules/spoke"
  for_each = local.spokes

  name               = "${local.p}-${each.key}"
  env                = each.key
  vpc_cidr           = each.value.cidr
  tgw_subnets        = each.value.tgw
  workload_subnets   = each.value.workload
  vm_az              = each.value.vm_az
  lab_mgmt_cidr      = cidrsubnet(each.value.cidr, 8, 255)
  internal_cidr      = var.internal_cidr
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  instance_type      = var.vm_instance_type
  key_name           = aws_key_pair.lab.key_name
  admin_cidrs        = var.admin_cidrs
  portal_cidrs       = each.key == var.server_env ? var.admin_cidrs : []
  testkit_image      = var.testkit_image
}
