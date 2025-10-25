# output "remote_state_bucket_arn" {
#  value = aws_s3_bucket.terraform_state.arn
#  description = "Remote Terraform state bucket ARN"
# }

# output "linux_key_pair" {
#  value = aws_key_pair.ec2-linux-key
# }

# output "splunk_hec_token" {
#   value = module.cloudtrail.hec_token_value
#   sensitive = true
# }

output "federated_sentinel_role_arn" {
  description = "Federated role created for Microsoft Sentinel using OpenID"
  value = module.cloudtrail.federated_sentinel_role_arn
}

output "cloudtrail_bucket_arn" {
  description = "CloudTrail bucket"
  value = module.cloudtrail.cloudtrail_bucket_arn
}

output "ec2_instance_id" {
    description = "ec2 instance id"
    value = module.ec2.instance_id
}
