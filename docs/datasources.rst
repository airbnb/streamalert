Datasources
=============

StreamAlert supports:

* Amazon S3
* AWS Kinesis Streams
* Log Forwarding Agents\*
* Code/Applications\*

\* *must send to a Kinesis Stream*

Amazon S3
----------

StreamAlert supports data analysis and alerting for logs written to configured Amazon S3 buckets.
This is achieved via Amazon S3 Event Notifications looking for an event type of ``s3:ObjectCreated:*``

Example AWS use-cases:

* **CloudTrail** logs
* **AWS Config** logs
* **S3 Server Access logs**

Example non-AWS use-cases:

* Host logs (syslog, auditd, osquery, ...)
* Network logs (Palo Alto Networks, Cisco, ...)
* Web Application logs (Apache, nginx, ...)
* SaaS logs (Box, OneLogin, …)


Log Forwarding Agents
----------------------

StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion.

Log forwarding agents that support AWS Kinesis Streams:

* **logstash**
* **fluentd**
* **aws-kinesis-agent**
* **osquery**


Code/Applications
----------------------

StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion.

Your code can send data to an AWS Kinesis Stream via:

* AWS SDK (Streams API)
* KPL (Amazon Kinesis Producer Library)


AWS Kinesis Streams
-------------------

StreamAlert can utilize existing stream(s) and/or create/deploy new streams to support log forwarding agents or code/applications.






