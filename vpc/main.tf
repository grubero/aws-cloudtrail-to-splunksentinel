# VPC setup for one EC2 running Splunk9.4 on RHEL9


data "terraform_remote_state" "remote_state_bucket" {
  backend = "s3"

  config = {
    bucket = "<obfuscated bucket name>"
    key = "terraform.tfstate"
    region = "ap-southeast-2"
    use_lockfile = true
  }
}

resource "aws_vpc" "vpc_cloudwatch_siem" {
    cidr_block = "172.16.0.0/26"
    enable_dns_hostnames = true

    tags = {
        Name = "vpc_cloudwatch_siem"
    }
}

resource "aws_subnet" "subnet_cloudwatch_siem" {
    vpc_id = aws_vpc.vpc_cloudwatch_siem.id
    cidr_block = "172.16.0.0/26"
    availability_zone = "ap-southeast-2b"

    tags = {
        Name = "subnet-cloudwatch-siem-ap-southeast-2b"
    }
}


resource "aws_security_group" "sg_cloudwatch_siem" {
    name = "AWSCloudWatchToSIEM Security Group"
    vpc_id = aws_vpc.vpc_cloudwatch_siem.id
}

resource "aws_vpc_security_group_ingress_rule" "ingress_https" {
  security_group_id = aws_security_group.sg_cloudwatch_siem.id
  cidr_ipv4 = var.allowed_ip
  from_port = 443
  ip_protocol = "tcp"
  to_port = 443

  tags = {
      Name = "HTTPS"
  }  
}

resource "aws_vpc_security_group_ingress_rule" "ingress_ssh" {
  security_group_id = aws_security_group.sg_cloudwatch_siem.id
  cidr_ipv4 = var.allowed_ip
  from_port = 22
  ip_protocol = "tcp"
  to_port = 22

  tags = {
      Name = "SSH"
  }    
}

resource "aws_vpc_security_group_ingress_rule" "ingress_splunk_web" {
  security_group_id = aws_security_group.sg_cloudwatch_siem.id
  cidr_ipv4 = var.allowed_ip
  from_port = 8000
  to_port = 8000
  ip_protocol = "tcp"

  tags = {
      Name = "Splunk Web Console"
  }    
}

resource "aws_vpc_security_group_ingress_rule" "ingress_splunk_public" {
  security_group_id = aws_security_group.sg_cloudwatch_siem.id
  cidr_ipv4 = "13.211.12.0/26"  # Amazon Data Firehose public access in ap-southeast-2 region
  from_port = 8088
  to_port = 8088
  ip_protocol = "tcp"

  tags = {
      Name = "Public access to Firehose in ap-southeast-2 region"
  }  
}

# Opening port 80 for HTTP is only needed when setting up a new TLS certificate using certbot, otherwise keep this 
# resource commented out

# resource "aws_vpc_security_group_ingress_rule" "ingress_http" {
#   security_group_id = aws_security_group.sg_cloudwatch_siem.id
#   cidr_ipv4 = "0.0.0.0/0"
#   from_port = 80
#   to_port = 80
#   ip_protocol = "tcp"

#   tags = {
#       Name = "Caution HTTP access"
#   }  
# }

resource "aws_vpc_security_group_egress_rule" "egress_all" {
  security_group_id = aws_security_group.sg_cloudwatch_siem.id
  cidr_ipv4 = "0.0.0.0/0"
  ip_protocol = "-1"
}

resource "aws_internet_gateway" "internet_gw_cloudwatch_siem" {
    vpc_id = aws_vpc.vpc_cloudwatch_siem.id

    tags = {
        Name = "AWSCloudWatchToSIEM Internet Gateway"
    }
}

resource "aws_route_table" "rtb_cloudwatch_siem" {
  vpc_id = aws_vpc.vpc_cloudwatch_siem.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gw_cloudwatch_siem.id
  }

  tags = {
    Name = "AWSCloudWatchToSIEM Route Table"
  }
}

resource "aws_main_route_table_association" "a" {
  vpc_id = aws_vpc.vpc_cloudwatch_siem.id
  route_table_id = aws_route_table.rtb_cloudwatch_siem.id
}



