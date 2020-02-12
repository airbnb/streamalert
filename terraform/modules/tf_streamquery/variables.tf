#
#
#

# The "prefix" is a namespace under which all resources are nested. This is especially important
# on staging or shared environments where multiple copies of a single StreamQuery could be
# deployed. On such environment, it typically adopts the form:
#
#     {username}{date}
#
# On production, this variable will typically have the value "airbnb".
variable "prefix" {
  description = "Namespace under which all AWS resources are named"
  type        = string
}

# StreamQuery is not a particularly CPU intensive system as it delegates the majority of work
# to AWS Athena. Currently 128 MB seems to be plenty.
variable "lambda_memory" {
  description = "The memory in megabytes allocated to the StreamQuery lambda function"
  type        = string
  default     = 128
}

# The AWS Account Id is used to generate the ARN of various resources. This configuration
# ASSUMES that both the Athena and Kinesis streams being accessed belong to the same AWS acccount
# that StreamQuery is being deployed to.
variable "aws_account_id" {
  description = "The AWS Account Id that StreamQuery is deployed to"
  type        = string
}

# The region is used to generate the ARN of various resources. Same as aws_account_id, this
# configuration assumes the region is the same across all accessed resources.
variable "aws_region" {
  description = "The AWS Region that StreamQuery is deployed to"
  type        = string
  default     = "us-east-1"
}

# The AWS Lambda timeout in seconds. Lambda will prematurely terminate after these many
# seconds.
#
# Due to StreamQuery being designed to run in small bursts of nonblocking operations, this
# value can be intentionally set low.  Something like 30 seconds should be enough.
variable "lambda_timeout" {
  description = "The timeout in seconds for the StreamQuery lambda"
  type        = string
  default     = 30
}

# Integer number of days to retain CloudWatch logs for the Lambda function. 14 is ok.
variable "lambda_log_retention" {
  description = "Number of days to retain CloudWatch logs for the Lambda function"
  type        = string
  default     = 14
}

# Integer number of Lambda errors to tolerate within the error_period before the Alarm triggers
variable "lambda_error_threshold" {
  description = "The number of lambda errors tolerated within the error period before an Alarm triggers"
  type        = string
  default     = 5
}

# Integer number of seconds for each error period
variable "lambda_error_period" {
  description = "The number of seconds for each Lambda function error period"
  type        = string
  default     = 300
}

# Boolean determining whether alarms are enabled or disabled
variable "lambda_alarms_enabled" {
  description = "Whether or not Alarms are enabled"
  type        = string
  default     = true
}

# String tag that is given to the StreamQuery resources, to make them easy to search.
variable "tag_name" {
  description = "A string tag that is given the StreamQuery lambda, making it easier to search"
  type        = string
  default     = "streamquery"
}

# S3 bucket where Lambda source code is deployed to
# Prod:  airbnb-csirt-lambda-source
# Stage: lambda-source-csirt
//variable "lambda_source_s3_bucket_name" {
//  description = "The S3 bucket name where Lambda source code is deployed to"
//  type        = string
//}

# ARN of the KMS Key that performs SSE of lambda source code
# Prod:  arn:aws:kms:us-east-1:569589067625:key/b2962a2e-1c7f-4a52-b0a0-893d3568d309
# Stage: arn:aws:kms:us-east-1:009715504418:key/5a7c7553-2dfe-4f02-ad3d-d6ed42fb597d
//variable "lambda_source_s3_bucket_kms_key_arn" {
//  description = "The KMS key used to do SSE on Lambda source code stored in the S3 bucket"
//  type        = string
//}

# Prod:  airbnb_csirt_stream_alert_kinesis
# Stage: ryxias20190211_prod_stream_alert_kinesis
variable "destination_kinesis_stream" {
  description = "The name of the target Kinesis stream, NOT the full ARN"
  type        = string
}

# Prod:  streamalert
# Stage: ryxias20190211_streamalert
variable "athena_database" {
  description = "The target Athena database to query"
  type        = string
}

# Prod:  aws-athena-query-results-569589067625-us-east-1
# Stage: aws-athena-query-results-009715504418-us-east-1
variable "athena_results_bucket" {
  description = "The destination S3 bucket where Athena query results are saved"
  type        = string
}

variable "athena_s3_buckets" {
  description = "A list of S3 bucket names that the target Athena is built over"
  type        = list(string)
}

# Prod:  production
# Stage: stage
variable "streamquery_environment" {
  description = "A description of the streamquery environment, which ultimately ends up just being tags on query filters"
  type        = string
}

