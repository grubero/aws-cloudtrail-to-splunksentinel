variable "private_ami" {
    description = "AMI for the EC2 that runs RHEL9"
    type = string
}

variable "ebs_kms_key" {
    description = "KMS key for ebs volumes"
    type = string
}

variable "ec2_linux_key_id" {
    description = "EC2 key pair"
    type = string
}

variable "allowed_ip" {
    description = "Allowed public subnet to EC2 running Splunk instance"
    type = string
}

variable "cloudtrail_bucket_arn" {
  description = "CloudTrail bucket to allow for SplunkEC2RoleSTS role"
}