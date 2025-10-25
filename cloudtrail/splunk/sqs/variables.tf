variable "cloudtrail_sns_topic_arn" {
    description = "SNS Fanout to Splunk SQS"
    type = string
}

variable "cloudtrail_bucket_arn" {
  description = "CloudTrail bucket"
  type = string
}