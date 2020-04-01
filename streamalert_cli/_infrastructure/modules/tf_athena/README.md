# Athena Partitioner Permissions
This module adds IAM permissions and other specific resources needed in the Athena partitioner function:
  * Athena Database for querying alerts and historical data
  * S3 Bucket for storing the results of Athena queries
  * SQS Queue for receiving event notifications from S3 buckets
  * S3 Event Notifications for sending messages to SQS Queue when objects are created
  * KMS Key and Alias for encrypting/decrypting messages on SQS Queue
  * Permissions for sending data to SQS Queue and reading/writing data in S3
