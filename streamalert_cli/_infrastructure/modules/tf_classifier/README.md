# Classifier Permissions
This module adds IAM permissions and other specific resources needed in the classifier function:
  * Permissions for sending data to StreamAlert Data Firehoses
  * SQS Queue that the Rules Engine function reads from
  * Permissions for sending messages to the above SQS Queue
  * SNS topic subscription(s) for SNS topics that should be able to invoke the Classifier
