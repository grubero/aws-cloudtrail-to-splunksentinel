# aws-cloudtrail-to-splunksentinel
This repository contains self-contained Terraform IaC to setup AWS CloudTrail forwarding to Microsoft Sentinel and Splunk.

Submodule: cloudtrail.sentinel
Microsoft Sentinel - AWS Add-on S3 data connector (only option is pull method)

Submodule: cloudtrail.splunk.sqs
Splunk - S3-SQS via Splunk Add-on for AWS (pull method)

Submodule: cloudtrail.splunk.firehose
Splunk - Firehose via Splunk HTTP Event Collector (push method)

Terraform submodules ec2 and vpc are only to run an instance of Splunk Enterprise on a VM and are not needed for
production deployment.

The screenshots in the siem_screenshots directory show a scenario of a potential cyber attack where the 'block all public
access' to S3 buckets across the entire account setting has been disabled. This could be the first step for a malicious 
actor to gain access to commercial data in all S3 buckets within a single account. However, bucket resource permissions, 
access control lists and encryption (if properly setup and the keys have not been stolen) will still act as layers of 
security. This type of scenario is a major policy setting change and if it is unexpected then it should trigger an alert 
and be investigated. This setting can only be changed by a user with high privileges so could mean even more has been 
compromised than just S3. The screenshots show how the same single event would look on Microsoft Sentinel and Splunk. 
Data formatting to CIM standards and datamodels haven't been setup so field names are inconsistent but still show the 
same values for this same event on both SIEMs. The steps to setup Microsoft Sentinel and Splunk to ingest AWS CloudTrail 
are not included in this repository.

![plot](siem_screenshots/Sentinel%20s3blockpublicaccess%20false%20export.png)
![plot](siem_screenshots/Splunk-s3sqs%20s3blockpublicaccess%20false%20export.png)
![plot](siem_screenshots/Splunk-firehose%20s3blockpublicaccess%20false%20export.png)

Relevant links:

https://learn.microsoft.com/en-us/azure/sentinel/connect-aws?tabs=s3#manual-setup
https://www.splunk.com/en_us/blog/tips-and-tricks/how-to-ingest-any-log-from-aws-cloudwatch-logs-via-firehose.html


