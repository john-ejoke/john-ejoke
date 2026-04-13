
output "vpc_id" {
  description = "ID of the SOC VPC"
  value       = aws_vpc.soc_vpc.id
}

output "subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.soc_public_subnet.id
}

output "security_group_id" {
  description = "ID of the SOC security group"
  value       = aws_security_group.soc_sg.id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 target"
  value       = aws_instance.soc_analysis_node.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.soc_analysis_node.id
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i soc_key_v2.pem ubuntu@${aws_instance.soc_analysis_node.public_ip}"
}
