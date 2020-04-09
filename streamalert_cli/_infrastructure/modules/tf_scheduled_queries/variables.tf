/*
 *
 */
variable "prefix" {
  description = "Namespace under which all AWS resources are named"
  type        = string
}

variable "destination_kinesis_stream" {
  description = "The name of the target Kinesis stream, NOT the full ARN"
  type        = string
}

/*
 * The AWS Account Id is used to generate the ARN of various resources. This configuration
 * ASSUMES that both the Athena and Kinesis streams being accessed belong to the same AWS acccount
 * that StreamQuery is being deployed to.
 */
variable "account_id" {
  description = "The AWS Account Id that StreamQuery is deployed to"
  type        = string
}

variable "region" {
  description = "The AWS Region that StreamQuery is deployed to"
  type        = string
}

variable "athena_database" {
  description = "The target Athena database to query"
  type        = string
}

variable "athena_results_bucket" {
  description = "The destination S3 bucket where Athena query results are saved"
  type        = string
}

variable "athena_s3_buckets" {
  description = "A list of S3 bucket names that the target Athena is built over"
  type        = list(string)
}

variable "sfn_timeout_secs" {
  description = "The maximum time in seconds a state machine will run"
  type        = number
}

variable "sfn_wait_secs" {
  description = "The time interval in seconds to wait between checking whether Athena queries are complete"
  type        = number
}

variable "query_packs" {
  description = "The configuration of each query pack"
  default     = []

  /*
   * The structure of each item in this list is a dictionary with 3 keys:
   *  - name: Name of the query pack. This is passed to the cloudwatch event as a tag
   *  - schedule_expression: CloudWatch event schedule expression (e.g. "rate(1 hour)")
   *  - description: A string describing the query pack

  default = [
    {
      "name": "sample",
      "schedule_expression": "rate(1 hour)",
      "description": "Placeholder"
    }
  ]

  */
}


#
# Below are all variables proxied to the Lambda module that builds the StreamQuery lambda function
#
variable "lambda_handler" {}

variable "lambda_concurrency_limit" {
  default = -1
}

variable "lambda_log_level" {
  description = "logging level for the lambda function"
  type        = string
  default     = "info"
}

/*
 * Due to StreamQuery being designed to run in small bursts of nonblocking operations, this
 * value can be intentionally set low.  Something like 30 seconds should be enough.
 */
variable "lambda_timeout" {
  description = "The timeout in seconds for the StreamQuery lambda"
  type        = number
  default     = 30
}

/*
 * StreamQuery is not a particularly CPU intensive system as it delegates the majority of work
 * to AWS Athena. Currently 128 MB seems to be plenty.
 */
variable "lambda_memory" {
  description = "The memory in megabytes allocated to the StreamQuery lambda function"
  type        = number
  default     = 128
}

variable "lambda_log_retention_days" {
  description = "Number of days to retain CloudWatch logs for the Lambda function"
  type        = number
  default     = 14
}

variable "lambda_alarms_enabled" {
  description = "Whether or not Alarms are enabled"
  type        = string
  default     = true
}

variable "lambda_alarm_actions" {
  description = "List of ARNS"
  default     = []
}

variable "lambda_error_threshold" {
  description = "The number of lambda errors tolerated within the error period before an Alarm triggers"
  type        = number
  default     = 1
}

variable "lambda_error_period_secs" {
  description = "The number of seconds for each Lambda function error period"
  type        = number
  default     = 3600
}

variable "lambda_error_evaluation_periods" {
  type    = number
  default = 2
}
