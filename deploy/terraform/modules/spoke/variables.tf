variable "name" {
  description = "Name prefix of the environment VPC (e.g. fwtk-pro)"
  type        = string
}

variable "env" {
  description = "Environment name"
  type        = string
}

variable "vpc_cidr" {
  type = string
}

variable "tgw_subnets" {
  description = "TGW subnets per AZ → { az = cidr }"
  type        = map(string)
}

variable "workload_subnets" {
  description = "Workload subnets per AZ → { az = cidr }"
  type        = map(string)
}

variable "vm_az" {
  description = "AZ of the test VM"
  type        = string
}

variable "lab_mgmt_cidr" {
  description = "Lab-only management subnet (IGW + EIP for SSH)"
  type        = string
}

variable "internal_cidr" {
  description = "Summary of all internal ranges (routed via the data ENI)"
  type        = string
}

variable "transit_gateway_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "key_name" {
  type = string
}

variable "admin_cidrs" {
  type = list(string)
}

variable "portal_cidrs" {
  description = "Sources allowed to the testkit portal (tcp/80 on the management interface); empty = closed"
  type        = list(string)
  default     = []
}

variable "testkit_image" {
  type = string
}
