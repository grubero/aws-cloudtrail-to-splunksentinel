output "subnet_cloudwatch_siem" {
    value = aws_subnet.subnet_cloudwatch_siem
}

output "sg_cloudwatch_siem" {
    value = aws_security_group.sg_cloudwatch_siem
}