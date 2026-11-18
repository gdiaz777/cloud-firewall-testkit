###############################################################################
# Inspection VPC: TGW attachment in appliance mode and the GWLB endpoints
# (consumers of the GWLB endpoint service in the firewall VPC).
#
#   tgw-<az>      RT: 0.0.0.0/0 → GWLBe in the same AZ
#   firewall-<az> RT: 0.0.0.0/0 → TGW (return after inspection)
###############################################################################

resource "aws_vpc" "inspection" {
  cidr_block           = local.inspection.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.p}-inspection" }
}

resource "aws_subnet" "inspection_tgw" {
  for_each          = local.inspection.tgw
  vpc_id            = aws_vpc.inspection.id
  cidr_block        = each.value
  availability_zone = each.key
  tags              = { Name = "${local.p}-inspection-tgw-${each.key}" }
}

resource "aws_subnet" "inspection_firewall" {
  for_each          = local.inspection.firewall
  vpc_id            = aws_vpc.inspection.id
  cidr_block        = each.value
  availability_zone = each.key
  tags              = { Name = "${local.p}-inspection-firewall-${each.key}" }
}

resource "aws_vpc_endpoint" "gwlbe" {
  for_each          = local.inspection.firewall
  vpc_id            = aws_vpc.inspection.id
  vpc_endpoint_type = "GatewayLoadBalancer"
  service_name      = module.cp_gwlb.gwlb_service_name
  subnet_ids        = [aws_subnet.inspection_firewall[each.key].id]
  tags              = { Name = "${local.p}-gwlbe-${each.key}" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "inspection" {
  vpc_id             = aws_vpc.inspection.id
  subnet_ids         = [for s in aws_subnet.inspection_tgw : s.id]
  transit_gateway_id = aws_ec2_transit_gateway.this.id

  appliance_mode_support                          = "enable"
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = { Name = "${local.p}-inspection-attach" }
}

resource "aws_route_table" "inspection_tgw" {
  for_each = local.inspection.tgw
  vpc_id   = aws_vpc.inspection.id
  tags     = { Name = "${local.p}-inspection-tgw-rt-${each.key}" }
}

resource "aws_route" "inspection_tgw_to_gwlbe" {
  for_each               = local.inspection.tgw
  route_table_id         = aws_route_table.inspection_tgw[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe[each.key].id
}

resource "aws_route_table_association" "inspection_tgw" {
  for_each       = local.inspection.tgw
  subnet_id      = aws_subnet.inspection_tgw[each.key].id
  route_table_id = aws_route_table.inspection_tgw[each.key].id
}

resource "aws_route_table" "inspection_firewall" {
  for_each = local.inspection.firewall
  vpc_id   = aws_vpc.inspection.id
  tags     = { Name = "${local.p}-inspection-firewall-rt-${each.key}" }
}

# depends_on: a route to a TGW without attachment fails with InvalidTransitGatewayID.NotFound
resource "aws_route" "inspection_firewall_to_tgw" {
  for_each               = local.inspection.firewall
  route_table_id         = aws_route_table.inspection_firewall[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.this.id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.inspection]
}

resource "aws_route_table_association" "inspection_firewall" {
  for_each       = local.inspection.firewall
  subnet_id      = aws_subnet.inspection_firewall[each.key].id
  route_table_id = aws_route_table.inspection_firewall[each.key].id
}
