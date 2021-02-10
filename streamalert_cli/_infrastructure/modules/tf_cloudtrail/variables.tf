variable "primary_account_id" {
  type        = string
  description = "ID of the deployment account"
}

variable "region" {
  type        = string
  description = "AWS region where the CloudTrail resources should be created"
}

variable "prefix" {
  type        = string
  description = "Resource prefix namespace"
}

variable "cluster" {
  type        = string
  description = "Name of the cluster"
}

variable "s3_cross_account_ids" {
  type        = list(string)
  description = "List of external account IDs for which logging should be allowed to the S3 bucket"
}

variable "enable_logging" {
  default     = true
  description = "nables logging for the CloudTrail. Setting this to false will pause logging on the trail"
}

variable "is_global_trail" {
  default     = true
  description = "Log API calls from all AWS regions"
}

variable "s3_logging_bucket" {
  type        = string
  description = "Name of bucket where S3 logs should be sent"
}

variable "s3_bucket_name" {
  type        = string
  description = "Name to apply to the bucket used for storing CloudTrail logs"
}

variable "s3_event_selector_type" {
  type        = string
  default     = ""
  description = "Type of S3 object level logging to enable via CloudTrail. Choices are: 'ReadOnly', 'WriteOnly', 'All', or '', where '' disables this feature"
}

variable "send_to_sns" {
  type        = bool
  default     = false
  description = "Whether or not events should be sent to SNS when objects are created in S3. This creates an SNS topic when set to true"
}

variable "allow_cross_account_sns" {
  type        = bool
  default     = false
  description = "Allow account IDs specified in the s3_cross_account_ids variable to also send SNS notifications to the created SNS Topic"
}

variable "cloudwatch_logs_role_arn" {
  type        = string
  default     = null
  description = "ARN of the IAM role to be used for sending logs to the CloudWatch Logs Group"
}

variable "cloudwatch_logs_group_arn" {
  type        = string
  default     = null
  description = "ARN of the CloudWatch Logs Group to which CloudTrail logs should be sent"
}
