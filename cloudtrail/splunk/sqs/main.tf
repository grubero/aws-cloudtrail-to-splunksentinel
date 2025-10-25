########################################
### AWS CloudTrail via SQS to Splunk ###
########################################


data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "SplunkSQS_attachment_role_policy" {
  statement {
    sid = "AllowSplunkSQSQueue"
    effect = "Allow"

    actions = [
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
      "sqs:ListQueues"
    ]
    resources = ["arn:aws:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
  }
  statement {
    sid = "AllowSplunkSQSS3"
    effect = "Allow"

     actions = [
      "s3:AbortMultipartUpload", 
      "s3:GetBucketLocation", 
      "s3:GetObject", 
      "s3:ListBucket", 
      "s3:ListBucketMultipartUploads", 
      "s3:PutObject"
    ]

    resources = [
      "${var.cloudtrail_bucket_arn}/cloudtrail/*",
      "${var.cloudtrail_bucket_arn}/failed_firehose_deliveries/*"
      ]
      # Bucket owner enforcement enabled. No need for ACL conditions.
  }
}

resource "aws_iam_policy" "SplunkSQS_role_policy" {
  name = "SplunkSQSAndS3RolePolicy"
  policy = data.aws_iam_policy_document.SplunkSQS_attachment_role_policy.json
}

resource "aws_iam_role_policy_attachment" "SplunkSQS_role_policy_attachmentToSplunkSQSRole" {
  role = aws_iam_role.splunk_sqs_role.name
  policy_arn = aws_iam_policy.SplunkSQS_role_policy.arn
}

resource "aws_iam_role_policy_attachment" "SplunkSQS_role_policy_attachmentToEC2InstanceRole" {
  role = data.aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.SplunkSQS_role_policy.arn
}

data "aws_iam_policy_document" "splunk_sqs_assume_role_policy" {
  statement {
    sid = "AllowRoleAssumeFromSplunkEC2Role"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SplunkEC2Role"]
    }

    actions = ["sts:AssumeRole"]
    # Don't need a condition because role is explicitly specified
  }
}

resource "aws_iam_role" "splunk_sqs_role" {
  name = "SplunkSQSRole"
  assume_role_policy = data.aws_iam_policy_document.splunk_sqs_assume_role_policy.json
}

data "aws_iam_role" "ec2_instance_role" {
  name = "SplunkEC2Role"
}

#### SQS resources and policies ###

data "aws_iam_policy_document" "cloudtrail_splunk_sqs_policy" {
  statement {
    sid = "AllowS3NotificationToSplunkQueue"
    effect = "Allow"

    principals {
        type = "Service"
        identifiers = ["sns.amazonaws.com"]
    }

    actions = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.cloudtrail_splunk_queue.arn]

    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["${var.cloudtrail_sns_topic_arn}"]
    }   
  }
  statement {
    sid = "AllowMessageToSplunk"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.splunk_sqs_role.arn]
    }

    actions = [
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
      "sqs:ListQueues"
    ]
    resources = [aws_sqs_queue.cloudtrail_splunk_queue.arn]
  }
}

resource "aws_sqs_queue_policy" "cloudtrail_splunk_notification_sqs_policy" {
  queue_url = aws_sqs_queue.cloudtrail_splunk_queue.id
  policy = data.aws_iam_policy_document.cloudtrail_splunk_sqs_policy.json
}

# set 'using_dlq = 0' in $SPLUNK_HOME$/etc/system/local/inputs.conf to disable requirement for a dead-letter queue
resource "aws_sqs_queue" "cloudtrail_splunk_queue" {
  name = "cloudtrail-splunk-notification-queue"
  delay_seconds = 0 # want data to get to SIEM as quickly as possible
  max_message_size = 2048
  message_retention_seconds = 300 # how long messages are kept in the queue 
  visibility_timeout_seconds = 300 # how long a message stays hidden after retrieval
  receive_wait_time_seconds = 10
}


resource "aws_sns_topic_subscription" "cloudtrail_splunk_sqs_target" {
  topic_arn = var.cloudtrail_sns_topic_arn
  protocol = "sqs"
  endpoint = aws_sqs_queue.cloudtrail_splunk_queue.arn
}



