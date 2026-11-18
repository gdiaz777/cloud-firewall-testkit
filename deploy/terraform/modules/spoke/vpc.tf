###############################################################################
# Environment (spoke) VPC
#   - <name>-tgw-<az>      : TGW attachment subnets (one per AZ)
#   - <name>-workload-<az> : workload subnets, 0.0.0.0/0 → TGW
# Lab only:
#   - <name>-labmgmt       : subnet with IGW for SSH to the VM (out-of-band management)
###############################################################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name, Environment = var.env }
}

resource "aws_subnet" "tgw" {
  for_each = var.tgw_subnets

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = { Name = "${var.name}-tgw-${each.key}" }
}

resource "aws_subnet" "workload" {
  for_each = var.workload_subnets

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = { Name = "${var.name}-workload-${each.key}" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  vpc_id             = aws_vpc.this.id
  subnet_ids         = [for s in aws_subnet.tgw : s.id]
  transit_gateway_id = var.transit_gateway_id

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = { Name = "${var.name}-attach" }
}

# --- Workload: everything to the TGW (east-west and Internet egress) ----------

resource "aws_route_table" "workload" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-workload-rt" }
}

resource "aws_route" "workload_default" {
  route_table_id         = aws_route_table.workload.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.this]
}

resource "aws_route_table_association" "workload" {
  for_each = aws_subnet.workload

  subnet_id      = each.value.id
  route_table_id = aws_route_table.workload.id
}

# TGW subnets keep the main route table (local only), as usual.

# --- Lab management -----------------------------------------------------------

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-labmgmt-igw" }
}

resource "aws_subnet" "labmgmt" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.lab_mgmt_cidr
  availability_zone = var.vm_az

  tags = { Name = "${var.name}-labmgmt-${var.vm_az}" }
}

resource "aws_route_table" "labmgmt" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-labmgmt-rt" }
}

resource "aws_route" "labmgmt_default" {
  route_table_id         = aws_route_table.labmgmt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab.id
}

resource "aws_route_table_association" "labmgmt" {
  subnet_id      = aws_subnet.labmgmt.id
  route_table_id = aws_route_table.labmgmt.id
}
