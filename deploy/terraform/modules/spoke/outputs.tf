output "vpc_id" { value = aws_vpc.this.id }
output "vpc_cidr" { value = aws_vpc.this.cidr_block }
output "tgw_attachment_id" { value = aws_ec2_transit_gateway_vpc_attachment.this.id }
output "instance_id" { value = aws_instance.vm.id }
output "az" { value = var.vm_az }
output "mgmt_public_ip" { value = aws_eip.mgmt.public_ip }
output "workload_ip" { value = aws_network_interface.workload.private_ip }
