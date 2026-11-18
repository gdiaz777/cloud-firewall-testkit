###############################################################################
# CME access to this account through STS: an IAM user whose only permission is
# sts:AssumeRole → read-only role with an external ID. The user keys can only assume
# the role. deploy/mgmt/cme.sh loads them into CME (read from the state, never printed).
###############################################################################

resource "random_password" "cme_external_id" {
  length  = 32
  special = false
}

# Mode "user": IAM user with keys that can only assume the role (needs iam:CreateAccessKey).
# Mode "role": no IAM user here; the role trusts a broker IAM user of another account (var.cme_trusted_principals)
# whose keys are given to CME — for accounts whose SCPs forbid access keys (CME always needs keys).
locals {
  cme_user = var.cme_access_mode == "user"
}

resource "aws_iam_user" "cme" {
  count = local.cme_user ? 1 : 0
  name  = "${local.p}-cme"
  tags  = { Purpose = "Check Point CME - AssumeRole only" }
}

resource "aws_iam_access_key" "cme" {
  count = local.cme_user ? 1 : 0
  user  = aws_iam_user.cme[0].name
}

resource "aws_iam_role" "cme" {
  name = "${local.p}-cme-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.cme_user ? [aws_iam_user.cme[0].arn] : (length(var.cme_trusted_principals) > 0 ? var.cme_trusted_principals : ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:root"]) }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = random_password.cme_external_id.result } }
    }]
  })
}

data "aws_caller_identity" "me" {}

resource "aws_iam_user_policy" "cme_assume" {
  count = local.cme_user ? 1 : 0
  name  = "assume-cme-role"
  user  = aws_iam_user.cme[0].name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.cme.arn }]
  })
}

# Read permissions CME needs for GWLB (same as the official cme_iam_role_gwlb module)
resource "aws_iam_role_policy" "cme_read" {
  name = "cme-gwlb-read"
  role = aws_iam_role.cme.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "autoscaling:DescribeAutoScalingGroups",
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServiceConfigurations",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeTargetHealth",
      ]
      Resource = "*"
    }]
  })
}
