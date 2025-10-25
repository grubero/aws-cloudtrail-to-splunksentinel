variable "private_ami" {
    description = "AMI for the EC2 that runs RHEL9"
    type = string
}

variable "ebs_kms_key" {
  description = "KMS key for ebs volumes"
  type = string
}

variable "ec2_linux_key_id" {
  description = "EC2 key pair for RHEL9 VM running Splunk Enterprise"
  type = string
}

variable "splunk_hec_endpoint" {
  description = "FQDN of the VM running splunkd"
  type = string
}

variable "sentinel_workspace_id" {
  description = "Log Analytics Workspace ID for Sentinel"
  type = string
}

variable "allowed_ip" {
    description = "Allowed public subnet to EC2 running Splunk instance"
    type = string
}

