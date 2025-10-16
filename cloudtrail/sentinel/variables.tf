variable "sentinel_workspace_id" {
    description = "Log Analytics Workspace ID for Sentinel"
    type = string
}

variable "cloudtrail_sns_topic_arn" {
  description = "SNS Fanout to Sentinel SQS"
  type = string
}

variable "cloudtrail_bucket_arn" {
  description = "CloudTrail bucket"
  type = string
}