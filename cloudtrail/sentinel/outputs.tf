output "federated_sentinel_role" {
  description = "Federated role created for Microsoft Sentinel using OpenID"
  value = aws_iam_role.federated_sentinel_role
}

output "cloudtrail_sentinel_queue" {
    description = "cloudtrail-sentinel-notification-queue"
    value = aws_sqs_queue.cloudtrail_sentinel_queue
}

