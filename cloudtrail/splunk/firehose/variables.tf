variable "cloudtrail_bucket_arn" {
  description = "CloudTrail bucket"
  type = string
}

variable "splunk_hec_endpoint" {
  description = "FQDN of the VM running splunkd"
  type = string
}