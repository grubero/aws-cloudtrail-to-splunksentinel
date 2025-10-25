output "federated_sentinel_role_arn" {
  description = "Federated role created for Microsoft Sentinel using OpenID"
  value = module.sentinel-sqs.federated_sentinel_role.arn
}

output "cloudtrail_bucket_arn" {
  description = "Cloudtrail bucket"
  value = aws_s3_bucket.cloudtrail_bucket.arn
}
