variable "splunk_hec_endpoint" {
  description = "FQDN of the VM running splunkd"
  type = string
}

variable "sentinel_workspace_id" {
  description = "Log Analytics Workspace ID for Sentinel"
  type = string
}

