##########################################################
### CloudWatch Log Group via Amazon Firehose to Splunk ###
##########################################################

# Specific to ap-southeast-2 region

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# CloudWatch log group to receive the CloudTrail trail
resource "aws_cloudwatch_log_group" "cloudwatch_group_cloudtrail_sourced" {
  name            = "CloudTrail/logs"
  log_group_class = "STANDARD"
  skip_destroy    = false
  retention_in_days = 3
}

# CloudWatch log group to log Firehose streaming errors (optional)
# Firehose sets a compulsary log group name as '/aws/kinesisfirehose/<firehose name>'
resource "aws_cloudwatch_log_group" "cloudwatch_group_firehose_error" {
  name            = "/aws/kinesisfirehose/${aws_kinesis_firehose_delivery_stream.splunk_stream.name}"
  log_group_class = "STANDARD"
  skip_destroy    = false
  retention_in_days = 3
  tags = {
    Description = "Error logging for SplunkFirehoseStream"
  }
}

/*
Role policy for CloudTrail to stream to the "CloudTrail/logs" log group and then to Splunk via Firehose
(https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html)
Splunk specific access settings: # https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html#using-iam-splunk
Subscription filter permissions: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#FirehoseExample
*/

### CloudTrail streaming to a CloudWatch Log group ###

data "aws_iam_policy_document" "splunk_firehose_role_policy" {
  # One role to cover CloudWatch logs, Lambda and Firehose
  # https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html

  statement {
    sid = "AllowCloudTrailReadWrite"
    effect = "Allow"

    actions = ["cloudtrail:*Logging"]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
  }

  statement {
    sid    = "AWSCloudWatchLogs"
    effect = "Allow"

    actions   = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:GetLogRecord",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups",
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudwatch_group_cloudtrail_sourced.name}:*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudwatch_group_firehose_error.name}:*"]
  }

  statement {
    sid = "AllowLambdaExecution"

    effect = "Allow"
    actions = [
      "lambda:InvokeFunction", 
      "lambda:GetFunctionConfiguration"       
    ]
    resources = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"]
  }

  statement {
    sid = "AllowWriteCloudWatchLogToFirehoseRecord"
    effect = "Allow"

    actions = [
      "firehose:DescribeDeliveryStream",
      "firehose:PutRecord",
      "firehose:PutRecordBatch",
      "firehose:UpdateDestination"
    ]
    
    resources = [aws_kinesis_firehose_delivery_stream.splunk_stream.arn]
  }

  statement {
    sid = "FirehoseAllowS3"
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
  }

  statement {
    sid = "ReadHECSecret"
    effect = "Allow"

    actions = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:splunk_hec_token*"]
  }
}

resource "aws_iam_policy" "splunk_firehose_role_policy" {
    name = "SplunkFirehoseRolePolicy"
    policy = data.aws_iam_policy_document.splunk_firehose_role_policy.json
}

resource "aws_iam_role_policy_attachment" "splunk_firehose_role_policy" {
  role = aws_iam_role.splunk_firehose_role.name
  policy_arn = aws_iam_policy.splunk_firehose_role_policy.arn
}

data "aws_iam_policy_document" "splunk_firehose_assumed_role_policy" {
  statement {
    sid = "AllowAssumeRoleByCloudTrail"
    effect = "Allow"

    principals {
        type = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]

    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  statement {
    sid = "AllowAssumeRoleByCloudWatchLogs"
    effect = "Allow"

    principals {
        type = "Service"
        identifiers = ["logs.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"] 
      # Important! Set the condition to :* and not the full arn of the 'CloudTrail/log' log group.
    }
  }

  statement {
    sid = "AllowAssumeRoleByFirehose"
    effect = "Allow"

    principals {
        type = "Service"
        identifiers = ["firehose.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["arn:aws:firehose:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:deliverystream/*"]
    }
  }

  statement {
    sid = "AllowAssumeRoleByLambda"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"]
    }
  }

  statement {
    sid = "AllowAssumeRoleBySecretsManager"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"
      values = ["arn:aws:firehose:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:deliverystream/*"]
    }
  }
}  

resource "aws_iam_role" "splunk_firehose_role" {
  name = "SplunkFirehoseRole"
  assume_role_policy = data.aws_iam_policy_document.splunk_firehose_assumed_role_policy.json
}

# Stream CloudWatch logs to Firehose
resource "aws_cloudwatch_log_subscription_filter" "cloudwatch_firehose_subscription" {
  depends_on = [aws_kinesis_firehose_delivery_stream.splunk_stream]
  name = "cloudwatch_firehose_subscription_filter"
  role_arn = aws_iam_role.splunk_firehose_role.arn

  log_group_name = aws_cloudwatch_log_group.cloudwatch_group_cloudtrail_sourced.name
  filter_pattern = ""     # send everything (not efficient)
  destination_arn = aws_kinesis_firehose_delivery_stream.splunk_stream.arn
}


####################
### Splunk Setup ###
####################

# Splunk server must be TLS certified by public CA - can't be self-signed.

resource "aws_kinesis_firehose_delivery_stream" "splunk_stream" {
  name = "SplunkFirehoseStream"
  destination = "splunk"

  splunk_configuration {
    hec_endpoint = var.splunk_hec_endpoint
    hec_acknowledgment_timeout = 180

    # Endpoint type:
    # Test mode only works with "Raw"
    hec_endpoint_type = "Event"

    # Records will be streamed every 10 seconds or once buffer reaches 1 MB, whichever is first.
    buffering_interval = 10 # seconds
    buffering_size = 1 # MB
    retry_duration = 300 # Retry only once every 5 minutes
    s3_backup_mode = "FailedEventsOnly"

    s3_configuration {
        role_arn = aws_iam_role.splunk_firehose_role.arn
        bucket_arn = var.cloudtrail_bucket_arn
        error_output_prefix = "firehose_failed_deliveries/"
        buffering_size = 10
        buffering_interval = 400
        compression_format = "GZIP"
    }

    secrets_manager_configuration {
      enabled = "true"
      # secret must be stored as KV "hec_token":<token value>
      secret_arn = data.aws_secretsmanager_secret_version.splunk_hec_token_secret_latest_kv.arn
      role_arn = aws_iam_role.splunk_firehose_role.arn
    }

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name = "BufferSizeInMBs"
          parameter_value = "0.256"
        }
        parameters {
          parameter_name = "BufferIntervalInSeconds"
          parameter_value = "10"
        }
        parameters {
          parameter_name = "LambdaArn"
          parameter_value = "${aws_lambda_function.cloudwatch_firehose_splunk_function.arn}:$LATEST"
        }
        parameters {
          parameter_name = "RoleArn"
          parameter_value = aws_iam_role.splunk_firehose_role.arn
        }
      }
    }

    # Log destination and processing errors (optional)
    # If there is an API error saying "The specified log stream does not exist." then go to the console and manually
    # disable then re-enable CloudWatch error logging for this stream.
    cloudwatch_logging_options {
      enabled = "true"
      log_group_name = "/aws/kinesisfirehose/SplunkFirehoseStream"
      log_stream_name = "DestinationDelivery"
    }
  }
}

resource "aws_lambda_function" "cloudwatch_firehose_splunk_function" {
  filename = "${path.module}/lambda/Cloudwatch2FH2HECv2.py.zip"
  handler = "Cloudwatch2FH2HECv2.lambda_handler"
  function_name = "FirehoseSplunkTransform"
  runtime = "python3.13"
  role = aws_iam_role.splunk_firehose_role.arn
  description = "Stream events from AWS CloudWatch Logs to Splunk's HTTP event collector"

  memory_size = 128 # MB
  timeout = 60 # seconds
}

data "aws_secretsmanager_secret" "splunk_hec_token_secret" {
  name = "splunk_hec_token_kv"
}

data "aws_secretsmanager_secret_version" "splunk_hec_token_secret_latest_kv" {
  secret_id = data.aws_secretsmanager_secret.splunk_hec_token_secret.id
}



