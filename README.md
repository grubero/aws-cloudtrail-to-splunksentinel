# aws-cloudtrail-to-splunksentinel
This repository contains IaC (in Terraform) to setup a self-contained environment as a proof-of-concept in AWS to 
forward AWS CloudTrail to two Security Information and Event Management (SIEM) systems simultaneously: Microsoft Sentinel 
and Splunk. These Terraform modules can be used as a baseline to setup your own environment using either SIEM. All 
necessary roles, permissions, keys, secrets etc. need to be setup to suit your environment. The steps to configure 
the plugins and various settings on Microsoft Sentinel and Splunk are specific to your environment. These steps are not 
included in this repository but can be found online. Two useful links are listed below.

Submodule: cloudtrail.sentinel
Microsoft Sentinel - AWS Add-on S3 data connector (only option is pull method)

Submodule: cloudtrail.splunk.sqs
Splunk - S3-SQS via Splunk Add-on for AWS (pull method)

Submodule: cloudtrail.splunk.firehose
Splunk - Firehose via Splunk HTTP Event Collector (push method)

Terraform modules ec2 and vpc are only to run a temporary instance of Splunk Enterprise on a VM and not needed for 
production deployment.

[Concept Diagram](./AWS%20CT%20to%20Splunk%20and%20Sentinel%20Concept%20Diagram.pdf)

These screenshots show what an analyst would see in a scenario of a potential cyber attack where the 'block all public
access' to S3 buckets across the entire account setting in AWS has been disabled. This could be the first step for a 
malicious actor to gain access to data in all S3 buckets of a single account. Bucket resource permissions, access control
lists and encryption however (if properly setup and the keys have not been stolen) still act as layers of security. This 
type of scenario is a major policy setting change and if it is unexpected should be investigated. This setting can only 
be changed by a user with high privileges and could mean more than just S3 buckets have been compromised. The screenshots 
show how the _same_ single event `3dbb79cf-2d35-402b-bef0-7ecca76d94e4` would look on Microsoft Sentinel and Splunk.

![Microsoft Sentinel - AWS Add-on S3 data connector](siem_screenshots/Sentinel%20s3blockpublicaccess%20false%20export.png)
![Splunk - S3-SQS](siem_screenshots/Splunk-s3sqs%20s3blockpublicaccess%20false%20export.png)
![Splunk - Firehose](siem_screenshots/Splunk-firehose%20s3blockpublicaccess%20false%20export.png)

Relevant links:

https://learn.microsoft.com/en-us/azure/sentinel/connect-aws?tabs=s3#manual-setup

https://www.splunk.com/en_us/blog/tips-and-tricks/how-to-ingest-any-log-from-aws-cloudwatch-logs-via-firehose.html

