output "environments" {
  description = "Test VM per environment"
  value = {
    for k, m in module.spoke : k => {
      az             = m.az
      instance_id    = m.instance_id
      mgmt_public_ip = m.mgmt_public_ip
      workload_ip    = m.workload_ip
      vpc_cidr       = m.vpc_cidr
    }
  }
}

output "server_env" {
  value = var.server_env
}

output "egress_nat_ips" {
  value = { for az, e in aws_eip.nat : az => e.public_ip }
}

output "firewall" {
  value = {
    gwlb_name         = module.cp_gwlb.gwlb_name
    gwlb_service_name = module.cp_gwlb.gwlb_service_name
    template_name     = var.cp_configuration_template
    management_name   = var.cp_management_server
  }
}

output "cme_sts" {
  description = "Data for the CME AWS account (keys are sensitive)"
  sensitive   = true
  value = {
    role_arn          = aws_iam_role.cme.arn
    external_id       = random_password.cme_external_id.result
    access_key_id     = try(aws_iam_access_key.cme[0].id, "")
    secret_access_key = try(aws_iam_access_key.cme[0].secret, "")
  }
}
