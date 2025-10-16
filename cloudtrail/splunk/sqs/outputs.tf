output "cloudtrail_splunk_queue" {
    description = "cloudtrail-splunk-notification-queue"
    value = aws_sqs_queue.cloudtrail_splunk_queue
}