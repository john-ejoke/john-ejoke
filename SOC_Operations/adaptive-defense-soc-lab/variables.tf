variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-northeast-1" # Tokyo
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "vpc_cidr" {
  description = "CIDR block for the SOC VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "wazuh_manager_endpoint" {
  description = "Wazuh Manager address (Tailscale IP or hostname)"
  type        = string
  default     = "100.83.231.37"
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
  default     = "soc-key-v2"
}
