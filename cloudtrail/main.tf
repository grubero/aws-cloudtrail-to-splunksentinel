# CloudTrail module - This module is needed no matter if Sentinel or Splunk is being used.


data "terraform_remote_state" "remote_state_bucket" {
  backend = "s3"

  # backend values for statebucket must be hardcoded (Terraform limitation)
  config = {
    bucket = "<obfuscated bucket name>"
    key = "terraform.tfstate"
    region = "ap-southeast-2"
    use_lockfile = true
  }
}

module "sentinel-sqs" {
  source = "./sentinel"

  sentinel_workspace_id = var.sentinel_workspace_id
  cloudtrail_sns_topic_arn = aws_sns_topic.cloudtrail_bucket_sns_topic.arn
  cloudtrail_bucket_arn = aws_s3_bucket.cloudtrail_bucket.arn
}

module "splunk-sqs" {
  source = "./splunk/sqs"

  cloudtrail_sns_topic_arn = aws_sns_topic.cloudtrail_bucket_sns_topic.arn
  cloudtrail_bucket_arn = aws_s3_bucket.cloudtrail_bucket.arn
}

module "splunk-firehose" {
  source = "./splunk/firehose"

  cloudtrail_bucket_arn = aws_s3_bucket.cloudtrail_bucket.arn
  splunk_hec_endpoint = var.splunk_hec_endpoint
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  trail_name = "logs-to-siem"
}

# Comment out anything related to CloudWatch logs if not streaming to Splunk via Firehose
data "aws_cloudwatch_log_group" "cloudwatch_group_cloudtrail_sourced" {
  depends_on = [module.splunk-firehose.cloudwatch_group_cloudtrail_sourced]
  name = "CloudTrail/logs"
}

data "aws_iam_role" "cloudwatchlog_role" {
  name = "SplunkFirehoseRole"
}

resource "aws_cloudtrail" "cloudtrail_events" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]

  name = local.trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.id
  s3_key_prefix = "cloudtrail"
  include_global_service_events = true # collect IAM type events
  enable_log_file_validation = false # set to true in a production environment

  # Comment out if not using CloudWatch logs and Firehose
  cloud_watch_logs_group_arn = "${data.aws_cloudwatch_log_group.cloudwatch_group_cloudtrail_sourced.arn}:*"
  cloud_watch_logs_role_arn = "${data.aws_iam_role.cloudwatchlog_role.arn}"

  # Specify events that Cloudtrail should log (including from different regions and accounts if applicable)

  advanced_event_selector {
    name = "Log all management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "Don't log when CloudTrail writes a log file to S3"
    # Don't log write actions of the log bucket otherwise it will create an infinite loop

    field_selector {
      field = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field = "resources.ARN"
      not_starts_with = [aws_s3_bucket.cloudtrail_bucket.id]
    }

    field_selector {
      field = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }

  advanced_event_selector {
    name = "Don't log when Terraform locks remote state"

    field_selector {
      field = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field = "resources.ARN"
      not_starts_with = ["<obfuscated bucket name>"]
    }

    field_selector {
      field = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid = "AllowFailedDeliveriesWrite"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SplunkFirehoseRole"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/*"]
  }
  
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/*"]
  }

  # https://github.com/Azure/Azure-Sentinel/blob/master/DataConnectors/AWS-S3/AwsRequiredPolicies.md
  statement {
    sid    = "AllowFederatedSentinelRoleCloudTrailLogfileRead"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.sentinel-sqs.federated_sentinel_role.arn]
    }

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
  }

 # Allow Firehose to put failed deliveries
  statement {
    sid = "AllowSplunkFirehoseRoleFailedLogfiles"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [data.aws_iam_role.cloudwatchlog_role.arn]
    }

    # actions = [
    #   "s3:AbortMultipartUpload", 
    #   "s3:GetBucketLocation", 
    #   "s3:GetObject", 
    #   "s3:ListBucket", 
    #   "s3:ListBucketMultipartUploads", 
    #   "s3:PutObject"
    # ]

    # Terraform gives error about "MalformedPolicy: Action does not apply to any resource(s) in statement" when 
    # setting actions to include "s3:ListBucket". Have to specify "s3:*" instead.
    # Fine tune action to read and write only later
    actions = [
      "s3:*"
    ]    
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/firehose_failed_deliveries/*"]
  }

  statement {
    sid = "RestrictToTLSRequestsOnly"
    effect = "Deny"

    principals {
      type = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [aws_s3_bucket.cloudtrail_bucket.arn]

    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = ["false"]
    }
  }
}

# A single S3 bucket can be used to retrieve CloudTrail logs from multiple accounts by seting up a SQS in each account 
# to a central bucket with multi-account permissions. Refer to 
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-set-bucket-policy-for-multiple-accounts.html 
# for more information.

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# A single bucket to store: 
#   CloudTrail log files
#   Failed Firehose record deliveries (if Splunk via Firehose is being used)
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket_prefix = "<obfuscated>"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "disable_public_access_to_cloudtrail_logs" {
    bucket = aws_s3_bucket.cloudtrail_bucket.id
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
}

# S3 notification can't be sent in FIFO mode to either SNS or SQS
resource "aws_s3_bucket_notification" "cloudtrail_bucket_sns_notification" {
  depends_on = [aws_sns_topic.cloudtrail_bucket_sns_topic]
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  topic {
    topic_arn = aws_sns_topic.cloudtrail_bucket_sns_topic.arn
    events = ["s3:ObjectCreated:*"]
    # filter_prefix = "cloudtrail/"
    # filter_suffix = ".json.gz"
  }
}

resource "aws_sns_topic_policy" "cloudtrail_bucket_sns_policy" {
  arn = aws_sns_topic.cloudtrail_bucket_sns_topic.arn

  # Terraform bug requires SNS policy explicitly using aws_sns_topic_policy instead of an IAM statement, otherwise 
  # aws_s3_bucket_notification will keep complaining about "api error InvalidArgument: Unable to validate the following 
  # destination configurations". Similar to SQS bug.
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "AllowS3NotificationsToTopic"
      Effect = "Allow"

      Principal = {
        Service = "s3.amazonaws.com"
      }

      Action =  "sns:Publish"
      Resource = aws_sns_topic.cloudtrail_bucket_sns_topic.arn

      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_s3_bucket.cloudtrail_bucket.arn
        }
      }
    }]
  })
}

# SNS fanout to Sentinel and Splunk SQS queues 
resource "aws_sns_topic" "cloudtrail_bucket_sns_topic" {
  name = "cloudtrail-s3-topic"
}


