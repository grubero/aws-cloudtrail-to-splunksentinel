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


# Maintain one EC2 to run Splunk Enterprise. Run install_splunk.sh after creating the VM.

data "terraform_remote_state" "remote_state_bucket" {
  backend = "s3"

  config = {
    bucket = "<obfuscated bucket name>"
    key = "terraform.tfstate"
    region = "ap-southeast-2"
    use_lockfile = true
  }
}

module "vpc" {
    source = "./../vpc"

    allowed_ip = var.allowed_ip
}

data "aws_caller_identity" "current" {}

locals {
  instance_type = "t3a.medium"
  availability_zone = "ap-southeast-2b"
}

data "aws_iam_policy_document" "ec2_instance_role_policy" {
  statement {
    sid = "AllowRolePassToSplunkSQSRole"
    effect = "Allow" 

    actions = ["iam:PassRole"]
    resources = [data.aws_iam_role.splunk_sqs_role.arn]
  }
  statement {
    sid = "AllowInstanceHandling"
    effect = "Allow"

    actions = [
      "iam:ListInstanceProfiles",
      "ec2:RunInstances", 
      "ec2:StopInstances", 
      "ec2:StartInstances"
      ]
    resources = [aws_instance.ec2-rhel9_splunk94.arn]
  }
}

data "aws_iam_role" "splunk_sqs_role" {
  name = "SplunkSQSRole"
}

resource "aws_iam_policy" "ec2_instance_role_policy" {
  name = "SplunkEC2RoleSTSPolicy"
  policy = data.aws_iam_policy_document.ec2_instance_role_policy.json
}

resource "aws_iam_role_policy_attachment" "ec2_instance_role_policy_attach" {
  role = aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.ec2_instance_role_policy.arn
}

data "aws_iam_policy_document" "ec2_instance_assume_role_policy" {
  statement {
    sid = "STSAssumeRole"
    effect = "Allow"
 
    principals {
      type = "Service"
      identifiers = [
        "ec2.amazonaws.com"
      ]
    }
   
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ec2_instance_role" {
  name = "SplunkEC2Role"
  assume_role_policy = data.aws_iam_policy_document.ec2_instance_assume_role_policy.json
}

/*
Note: This proof of concept runs Splunk Enterprise in EC2 so it is an advantage to use STS with the instance
profile to provide temporary AWS credentials to Splunk without creating a new IAM user. Running Splunk on a
different cloud provider or on-prem will require the extra step to create an IAM user. Make the necessary 
IAM settings in the Splunk Add-on for AWS to suit.
*/

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "SplunkEC2RoleSTSInstanceProfile"
  role = aws_iam_role.ec2_instance_role.name
}

# Reference key by ARN instead of ID to avoid force replacement of EC2s on new applies
data "aws_kms_key" "ebs_kms_key_data" {
  key_id = var.ebs_kms_key
}

resource "aws_instance" "ec2-rhel9_splunk94" {
    ami = var.private_ami
    instance_type = local.instance_type
    iam_instance_profile = "SplunkEC2RoleSTSInstanceProfile"

    network_interface {
      network_interface_id = aws_network_interface.nic1_rhel9.id
      device_index = 0
    }

    key_name = data.aws_key_pair.ec2-linux-key.key_name

    root_block_device {
      delete_on_termination = false
      encrypted = true
      kms_key_id = data.aws_kms_key.ebs_kms_key_data.arn
      tags = {
        Name = "RHEL9_Splunk-root"
      }
    }

    ebs_block_device {
     device_name = "/dev/sdb"
     delete_on_termination = false
     encrypted = true
     kms_key_id = data.aws_kms_key.ebs_kms_key_data.arn
     tags = {
       Name = "RHEL9_Splunk-sdb"
     }
    }

    tags = {
        Name = "RHEL9-Splunk94"
        availability_zone = local.availability_zone
    }
}

# The aws_key_pair resource does not create the actual key pair - it has to be manually created.

# Change from using key pairs as a managed resource to data block. Manually set up the key pair in AWS console.
# resource "aws_key_pair" "ec2-linux-key" {
#   key_name = "ec2-sept-2025"
#   public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTG5AAAAIDhTnSyPczE55Sf3zu5NcB26EqY4aSyl9q5mjbx2aK9C ec2-sept-2025.pub"

#   tags = {
#     UsedFor = "AWSCloudTrailToSIEM Linux machines"
#   }
# }

data "aws_key_pair" "ec2-linux-key" {
 key_name = "ec2-sept-2025"

 filter {
   name = "key-pair-id"
   values = [var.ec2_linux_key_id]
 }
}

resource "aws_network_interface" "nic1_rhel9" {
  subnet_id = module.vpc.subnet_cloudwatch_siem.id
  private_ips = ["172.16.0.17"]
  security_groups = [module.vpc.sg_cloudwatch_siem.id]

  tags = {
    Name = "RHEL9 NIC"
  }
}

### Elastic IPs ###

# Note: Commenting or uncommenting the 'eip_rhel94' resource will require a new CA signed TLS certificate 
# to be created for any new IP address. Splunk Add-on for AWS won't work with a self-signed TLS certificate.

resource "aws_eip" "eip_rhel9" {
 network_interface = aws_network_interface.nic1_rhel9.id
 domain = "vpc"

  tags = {
    Name = "RHEL9 Elastic IP"
  }
}

