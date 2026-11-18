###############################################################################
# Egress VPC: centralized Internet egress (no inbound publishing).
#
#   tgw-<az> RT: 0.0.0.0/0  → NAT GW in the same AZ
#   nat-<az> RT: 0.0.0.0/0  → IGW
#                internal   → TGW (return to the spokes, through inspection)
###############################################################################

resource "aws_vpc" "egress" {
  cidr_block           = local.egress.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.p}-egress" }
}

resource "aws_internet_gateway" "egress" {
  vpc_id = aws_vpc.egress.id
  tags   = { Name = "${local.p}-egress-igw" }
}

resource "aws_subnet" "egress_tgw" {
  for_each          = local.egress.tgw
  vpc_id            = aws_vpc.egress.id
  cidr_block        = each.value
  availability_zone = each.key
  tags              = { Name = "${local.p}-egress-tgw-${each.key}" }
}

resource "aws_subnet" "egress_nat" {
  for_each          = local.egress.nat
  vpc_id            = aws_vpc.egress.id
  cidr_block        = each.value
  availability_zone = each.key
  tags              = { Name = "${local.p}-egress-nat-${each.key}" }
}

resource "aws_eip" "nat" {
  for_each   = local.egress.nat
  domain     = "vpc"
  tags       = { Name = "${local.p}-nat-eip-${each.key}" }
  depends_on = [aws_internet_gateway.egress]
}

resource "aws_nat_gateway" "egress" {
  for_each      = local.egress.nat
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.egress_nat[each.key].id
  tags          = { Name = "${local.p}-natgw-${each.key}" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "egress" {
  vpc_id             = aws_vpc.egress.id
  subnet_ids         = [for s in aws_subnet.egress_tgw : s.id]
  transit_gateway_id = aws_ec2_transit_gateway.this.id

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = { Name = "${local.p}-egress-attach" }
}

resource "aws_route_table" "egress_nat" {
  vpc_id = aws_vpc.egress.id
  tags   = { Name = "${local.p}-egress-nat-rt" }
}

resource "aws_route" "egress_nat_default" {
  route_table_id         = aws_route_table.egress_nat.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.egress.id
}

resource "aws_route" "egress_nat_to_tgw" {
  route_table_id         = aws_route_table.egress_nat.id
  destination_cidr_block = var.internal_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.this.id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route_table_association" "egress_nat" {
  for_each       = local.egress.nat
  subnet_id      = aws_subnet.egress_nat[each.key].id
  route_table_id = aws_route_table.egress_nat.id
}

resource "aws_route_table" "egress_tgw" {
  for_each = local.egress.tgw
  vpc_id   = aws_vpc.egress.id
  tags     = { Name = "${local.p}-egress-tgw-rt-${each.key}" }
}

resource "aws_route" "egress_tgw_to_nat" {
  for_each               = local.egress.tgw
  route_table_id         = aws_route_table.egress_tgw[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.egress[each.key].id
}

resource "aws_route_table_association" "egress_tgw" {
  for_each       = local.egress.tgw
  subnet_id      = aws_subnet.egress_tgw[each.key].id
  route_table_id = aws_route_table.egress_tgw[each.key].id
}
