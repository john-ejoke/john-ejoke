terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1" # Tokyo
}

# ─────────────────────────────────────────────────────────
# AMI Data Source — Ubuntu 24.04 Noble
# ─────────────────────────────────────────────────────────
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# ─────────────────────────────────────────────────────────
# VPC
# ─────────────────────────────────────────────────────────
resource "aws_vpc" "soc_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = { Name = "SOC-VPC" }
}

# ─────────────────────────────────────────────────────────
# Subnet
# ─────────────────────────────────────────────────────────
resource "aws_subnet" "soc_public_subnet" {
  vpc_id                  = aws_vpc.soc_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-northeast-1a"
  tags = { Name = "SOC-Public-Subnet" }
}

# ─────────────────────────────────────────────────────────
# Internet Gateway
# ─────────────────────────────────────────────────────────
resource "aws_internet_gateway" "soc_igw" {
  vpc_id = aws_vpc.soc_vpc.id
  tags   = { Name = "SOC-Internet-Gateway" }
}

# ─────────────────────────────────────────────────────────
# Route Table
# ─────────────────────────────────────────────────────────
resource "aws_route_table" "soc_route_table" {
  vpc_id = aws_vpc.soc_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.soc_igw.id
  }

  tags = { Name = "SOC-Route-Table" }
}

resource "aws_route_table_association" "soc_rta" {
  subnet_id      = aws_subnet.soc_public_subnet.id
  route_table_id = aws_route_table.soc_route_table.id
}

# ─────────────────────────────────────────────────────────
# Security Group
# ─────────────────────────────────────────────────────────
resource "aws_security_group" "soc_sg" {
  name        = "SOC-Security-Group"
  description = "SOC lab security group — SSH and HTTP"
  vpc_id      = aws_vpc.soc_vpc.id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict to your IP in production
  }

  ingress {
    description = "HTTP for vulnerability scanning"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "SOC-Security-Group" }
}

# ─────────────────────────────────────────────────────────
# Key Pair
# ─────────────────────────────────────────────────────────
resource "aws_key_pair" "soc_key" {
  key_name   = "soc-key-v2"
  public_key = file("${path.module}/soc_key_v2.pem.pub")
}

# ─────────────────────────────────────────────────────────
# EC2 — SOC Analysis Node / Vulnerable Target
# ─────────────────────────────────────────────────────────
resource "aws_instance" "soc_analysis_node" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.soc_public_subnet.id
  vpc_security_group_ids      = [aws_security_group.soc_sg.id]
  key_name                    = aws_key_pair.soc_key.key_name
  associate_public_ip_address = true

  user_data = file("${path.module}/user_data.sh")

  tags = { Name = "Tokyo-Vulnerable-Target" }
}

# ─────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────
output "target_public_ip" {
  description = "Public IP of the SOC analysis node"
  value       = aws_instance.soc_analysis_node.public_ip
}

output "target_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.soc_analysis_node.id
}
