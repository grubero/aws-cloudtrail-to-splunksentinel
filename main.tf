/*
MIT License

Copyright (c) 2025 Oliver Gruber

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

####################################################################################
### Terraform IaC - Forward AWS CloudTrail to Microsoft Sentinel and Splunk SIEM ###
####################################################################################

# Root Terraform module
# Run 'terraform init' from this directory

/* Notes about secrets and keys:
This IaC demonstration is a proof of concept for forwarding AWS CloudTrail logs to 
both Splunk and Microsoft Sentinel simultaneously in a self-enclosed environment.
The ec2 amd vpc modules are only for running a temporary Splunk instance for 
demonstration. Microsoft Sentinel is a cloud based SaaS and doesn't need this. 
To use this IaC to have CloudTrail connected to Splunk, Microsoft Sentinel or both, 
only the cloudtrail, cloudtrail.splunk and/or cloudtrail.sentinel submodules are needed.

Although some resources such as EBS volume keys, EC2 key pairs, KMS keys are 
created automatically, others need to be manually created (e.g. the Splunk HEC token).
This root terraform module needs to be run first to set up infrastructure and
then run again after manual KMS keys or Secrets Manager secrets are created to avoid
any 'chicken and egg' problems. Whether a key or secret needs to be created beforehand 
should be self-explanatory by whether it is a data or resource object.
*/


# bootstrap S3 bucket storing remote state
terraform {
  # Backend variables have to be hardcoded
  backend "s3" {
    bucket = "<obfuscated bucket name>"
    key = "terraform.tfstate"
    region = "ap-southeast-2"
    use_lockfile = true
  }

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
    region = "ap-southeast-2"

  default_tags {
    tags = {
      ManagedBy = "Terraform"
    }
  }
}

resource "aws_s3_bucket" "terraform_state" {
    bucket = "<obfuscated bucket name>"
    force_destroy = true # destroy all objects when the bucket is to be destroyed (i.e. when prevent_destroy = false)

    lifecycle {
        prevent_destroy = true
    }
}

resource "aws_s3_bucket_versioning" "enabled" {
    bucket = aws_s3_bucket.terraform_state.id
    versioning_configuration {
      status = "Enabled"
    }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
    bucket = aws_s3_bucket.terraform_state.id

    rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "AES256"
        }
    }
}

# Explicitly block all public access to the remote state S3 bucket
resource "aws_s3_bucket_public_access_block" "disable_public_access_to_state_bucket" {
    bucket = aws_s3_bucket.terraform_state.id
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
}

/*
Optional: Uncomment the ec2 module to create a temporary VM enclosed within the cloudwatch-vpc for ease of creation 
and destruction. Splunk will need to be install on this temporary machine which is outside the scope of this proof of 
concept project. Comment out the module if there is an existing Splunk instance to avoid creating a new virtual machine.
*/

module "ec2" {
    source = "./ec2"

    # Encrypting the EBS volumes within the enclosed proof of concept AWS environment is optional
    private_ami = var.private_ami
    ebs_kms_key = var.ebs_kms_key
    ec2_linux_key_id = var.ec2_linux_key_id
    allowed_ip = var.allowed_ip
    cloudtrail_bucket_arn = module.cloudtrail.cloudtrail_bucket_arn
}

module "cloudtrail" {
  source = "./cloudtrail"

  splunk_hec_endpoint = var.splunk_hec_endpoint
  sentinel_workspace_id = var.sentinel_workspace_id
}


