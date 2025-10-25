########################################################
### AWS CloudTrail via AWS SQS to Microsoft Sentinel ###
########################################################

# Note: Do not run the automatic setup Powershell scripts on the Azure GitHub repo (ConfigAwsS3DataConnectorScripts.zip) 
# after running this terraform code otherwise it will cause conflicts.

# Remember to add the SQS URL to the 'Amazon Web Services S3' data connector in Microsoft Sentinel by following the 
# manual setup instructions https://learn.microsoft.com/en-us/azure/sentinel/connect-aws?tabs=s3#manual-setup


data "aws_caller_identity" "current" {}


# Connect AWS to Sentinel using an OpenID Connect web identity provider and AWS assumed role
resource "aws_iam_openid_connect_provider" "sentinelconnector_openid_provider" {
  # Ref: https://learn.microsoft.com/en-us/azure/sentinel/connect-aws?tabs=s3#add-the-aws-role-and-queue-information-to-the-s3-data-connector

  url = "https://sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d/"
  client_id_list = ["api://1462b192-27f7-4cb9-8523-0f4ecb54b47e"]
}

data "aws_iam_policy_document" "federated_sentinel_role_policy" {
  # Source: https://github.com/Azure/Azure-Sentinel/blob/master/DataConnectors/AWS-S3/AwsRequiredPolicies.md
  statement {
    sid = "AllowSentinelReadAccessS3"
    effect = "Allow" 

    actions = ["s3:GetObject"]
    resources = ["${var.cloudtrail_bucket_arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
  }
  statement {
    sid = "AllowSentinelFullControlSQS"
    effect = "Allow"

    actions = [
      "sqs:DeleteMessage",
      "sqs:ReceiveMessage",
      "sqs:GetQueueUrl"
    ]
    resources = [aws_sqs_queue.cloudtrail_sentinel_queue.arn]
  }  
}

resource "aws_iam_policy" "federated_sentinel_role_policy" {
    name = "OIDC_FederatedMicrosoftSentinelRolePolicy"
    policy = data.aws_iam_policy_document.federated_sentinel_role_policy.json
}

resource "aws_iam_role_policy_attachment" "federated_sentinel_policy_attach" {
  role = aws_iam_role.federated_sentinel_role.name
  policy_arn = aws_iam_policy.federated_sentinel_role_policy.arn
}

data "aws_iam_policy_document" "federated_sentinel_assume_role" {
  statement {
    sid    = "GrantAccessToOpenIDFederatedRoleForSentinelConnector"
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d/"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d/:aud"
      values   = ["api://1462b192-27f7-4cb9-8523-0f4ecb54b47e"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:RoleSessionName"
      values   = ["MicrosoftSentinel_${var.sentinel_workspace_id}"]
    }

    actions   = ["sts:AssumeRoleWithWebIdentity"]
  }
}

resource "aws_iam_role" "federated_sentinel_role" {
  name = "OIDC_FederatedMicrosoftSentinelRole"
  assume_role_policy = data.aws_iam_policy_document.federated_sentinel_assume_role.json
}


######################################################
### SQS to AWS S3 connector for Microsoft Sentinel ###
######################################################

/*
Some sort of terraform apply timeout problem when a iam_policy_document is being used and a federated user is the principal. 
SQS policy for the Splunk version doesn't have the same problem when using an iam_policy_document and doesn't have a 
federated user. Using inline permissions instead. 
https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy
*/

resource "aws_sqs_queue_policy" "cloudtrail_sentinel_sqs_policy" {
  queue_url = aws_sqs_queue.cloudtrail_sentinel_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "AllowS3NotificationToSentinelQueue"
      Effect = "Allow"

      Principal = {
        Service = "sns.amazonaws.com"
      }

      Action = [
        "sqs:SendMessage",
        "sqs:DeleteMessage"
      ]       
      Resource = aws_sqs_queue.cloudtrail_sentinel_queue.arn

      Condition = {
        ArnEquals = {
        "aws:SourceArn" = "${var.cloudtrail_sns_topic_arn}"
        }   
      }
    },
    {
      Sid    = "AllowMessageToSentinel"
      Effect = "Allow"

      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.federated_sentinel_role.name}"
      }

      Action = [     
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueUrl",
        "sqs:ChangeMessageVisibility"
        ]
      Resource = aws_sqs_queue.cloudtrail_sentinel_queue.arn
    }]
  })
}

# The Amazon Web Services S3 data connector for Microsoft Sentinel doesn't support SQS in FIFO mode. Could be an issue 
# with event order and duplication but from observation there doesn't seem to be event duplication happening. Could be 
# an important issue when analysing sequence of events in a SIEM. Unclear whether the data connector handles 
# deduplication automatically.

resource "aws_sqs_queue" "cloudtrail_sentinel_queue" {
  name = "cloudtrail-sentinel-notification-queue"
  delay_seconds = 0 # want data to get to SIEM as quickly as possible
  max_message_size = 2048 # bytes
  message_retention_seconds = 300
  visibility_timeout_seconds = 30 # how long a message stays hidden after retrieval
  receive_wait_time_seconds = 10
}

resource "aws_sns_topic_subscription" "cloudtrail_sentinel_sqs_target" {
  topic_arn = var.cloudtrail_sns_topic_arn
  protocol = "sqs"
  endpoint = aws_sqs_queue.cloudtrail_sentinel_queue.arn
}


