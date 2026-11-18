data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_security_group" "mgmt" {
  name        = "${var.name}-labmgmt-sg"
  description = "Lab management: SSH to the test VM"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  # Testkit portal (server VM only, from specific sources)
  dynamic "ingress" {
    for_each = length(var.portal_cidrs) > 0 ? [1] : []
    content {
      description = "Testkit portal (HTTP)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = var.portal_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-labmgmt-sg" }
}

# Access control between environments is done by the firewall: the workload SG allows all internal
# traffic so it does not hide the firewall policy.
resource "aws_security_group" "workload" {
  name        = "${var.name}-workload-sg"
  description = "Test traffic between environments (filtered by the firewall)"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.internal_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-workload-sg" }
}

resource "aws_iam_role" "ec2" {
  name = "${var.name}-vm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.name}-vm-profile"
  role = aws_iam_role.ec2.name
}

resource "aws_network_interface" "mgmt" {
  subnet_id       = aws_subnet.labmgmt.id
  security_groups = [aws_security_group.mgmt.id]
  description     = "${var.name} lab management"
  tags            = { Name = "${var.name}-labmgmt-eni" }
}

resource "aws_eip" "mgmt" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.mgmt.id
  associate_with_private_ip = aws_network_interface.mgmt.private_ip

  tags       = { Name = "${var.name}-labmgmt-eip" }
  depends_on = [aws_internet_gateway.lab]
}

resource "aws_network_interface" "workload" {
  subnet_id       = aws_subnet.workload[var.vm_az].id
  security_groups = [aws_security_group.workload.id]
  description     = "${var.name} workload (inspected traffic)"
  tags            = { Name = "${var.name}-workload-eni" }
}

resource "aws_instance" "vm" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.key_name

  iam_instance_profile = aws_iam_instance_profile.ec2.name

  network_interface {
    network_interface_id = aws_network_interface.mgmt.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.workload.id
    device_index         = 1
  }

  # Docker + policy routing from the workload IP (internal ranges and Internet egress sourced from it → TGW)
  user_data = templatefile("${path.module}/templates/vm_userdata.sh.tftpl", {
    internal_cidr = var.internal_cidr
    image         = var.testkit_image
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }

  # user_data only runs on first boot: changing the template must not replace the VM
  lifecycle {
    ignore_changes = [user_data]
  }

  tags = { Name = "${var.name}-vm", Environment = var.env, TestkitEnv = var.env }
}
