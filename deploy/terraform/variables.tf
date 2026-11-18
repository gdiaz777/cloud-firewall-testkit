variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name"
  type        = string
  default     = "fwtk"
}

variable "admin_cidrs" {
  description = "Sources allowed to SSH to the test VMs and to open the portal"
  type        = list(string)
}

variable "ssh_public_key_file" {
  description = "Public key for the test VMs"
  type        = string
}

variable "environments" {
  description = "Environments: name → { cidr (/16), az (a|b) }"
  type        = map(object({ cidr = string, az = string }))
  default = {
    pro  = { cidr = "10.0.0.0/16", az = "b" }
    pre  = { cidr = "10.1.0.0/16", az = "a" }
    dev  = { cidr = "10.2.0.0/16", az = "b" }
    comm = { cidr = "10.3.0.0/16", az = "a" }
  }
}

variable "server_env" {
  description = "Environment that hosts the testkit server and portal"
  type        = string
  default     = "comm"
}

variable "internal_cidr" {
  description = "Summary covering every internal range"
  type        = string
  default     = "10.0.0.0/8"
}

variable "inspection_cidr" {
  type    = string
  default = "10.250.0.0/16"
}

variable "egress_cidr" {
  type    = string
  default = "10.251.0.0/16"
}

variable "firewall_cidr" {
  type    = string
  default = "10.252.0.0/16"
}

variable "vm_instance_type" {
  description = "Test VM type"
  type        = string
  default     = "c5n.large"
}

variable "testkit_image" {
  type    = string
  default = "ghcr.io/gdiaz777/cloud-firewall-testkit:latest"
}

# ---------- Check Point Cloud Firewall ----------
variable "cp_gateway_sic_key" {
  description = "SIC key; must match the CME template"
  type        = string
  sensitive   = true
}

variable "cp_gateway_password_hash" {
  description = "Gateway admin password hash (openssl passwd -6). Empty = SSH key only."
  type        = string
  default     = ""
  sensitive   = true
}

variable "cp_gateway_instance_type" {
  type    = string
  default = "c5n.xlarge"
}

variable "cp_gateway_version" {
  description = "Version and license, e.g. R81.20-PAYG-NGTP"
  type        = string
  default     = "R81.20-PAYG-NGTP"
}

variable "cp_min_group_size" {
  type    = number
  default = 2
}

variable "cp_max_group_size" {
  type    = number
  default = 4
}

variable "cp_gateways_addresses" {
  description = "Management addresses allowed to reach the gateways (Smart-1 Cloud has no fixed IPs → 0.0.0.0/0)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "cp_configuration_template" {
  description = "CME template name (x-chkp-template tag)"
  type        = string
}

variable "cp_management_server" {
  description = "CME management name (x-chkp-management tag)"
  type        = string
}
