###############################################################################
# TGW route tables
#
#   spokes-rt     : associated with every environment and egress.
#                   0.0.0.0/0 → inspection (every flow is inspected:
#                   east-west, egress and NAT return traffic).
#   inspection-rt : associated with inspection. Environments and egress propagate
#                   (return after inspection) + 0.0.0.0/0 → egress.
###############################################################################

resource "aws_ec2_transit_gateway_route_table" "spokes" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  tags               = { Name = "${local.p}-spokes-rt" }
}

resource "aws_ec2_transit_gateway_route_table" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  tags               = { Name = "${local.p}-inspection-rt" }
}

locals {
  inspected_attachments = merge(
    { for k, m in module.spoke : k => m.tgw_attachment_id },
    { egress = aws_ec2_transit_gateway_vpc_attachment.egress.id },
  )
}

resource "aws_ec2_transit_gateway_route_table_association" "spokes" {
  for_each                       = local.inspected_attachments
  transit_gateway_attachment_id  = each.value
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

resource "aws_ec2_transit_gateway_route" "spokes_to_inspection" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

resource "aws_ec2_transit_gateway_route_table_association" "inspection" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspection.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "inspection" {
  for_each                       = local.inspected_attachments
  transit_gateway_attachment_id  = each.value
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

resource "aws_ec2_transit_gateway_route" "inspection_to_egress" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}
