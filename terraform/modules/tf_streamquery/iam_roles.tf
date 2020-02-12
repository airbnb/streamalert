#
# iam_roles
#
#   This file houses all IAM policies relevant to StreamQuery
#

#
# Permissions for Lambda -> Athena, Kinesis, and other stuff
#
#   Notably, because we use a reusable Lambda module for the Lambda function, it automatically
#   creates the IAM Role
#

# Attach additional permissions to the auto-generated Lambda IAM Role
resource "aws_iam_role_policy" "lambda_permissions" {
  name   = "${var.prefix}_streamquery_lambda_permissions"
  role   = module.streamquery_lambda.role_id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# All of the relevant permissions to the StreamQuery Lambda function
data "aws_iam_policy_document" "lambda_permissions" {
  # Grant Lambda function access to AWS Athena (more complicated than it sounds)
  statement {
    sid    = "AllowLambdaToAccessAthenaService"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
    ]
    resources = [
      "arn:aws:athena:${var.aws_region}:${var.aws_account_id}:workgroup/primary",
    ]
  }

  statement {
    sid    = "AllowLambdaToAccessAthenaGlue"
    effect = "Allow"
    actions = [
      "glue:GetTable",
      "glue:GetDatabase",
      "glue:GetPartition",
      "glue:GetPartitions",
    ]
    resources = local.athena_glue_resources
  }
  statement {
    sid    = "AllowLambdaToWriteToAthenaQueryResultsS3Bucket"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
      "s3:CreateBucket",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${var.athena_results_bucket}",
      "arn:aws:s3:::${var.athena_results_bucket}/*",
    ]
  }
  statement {
    sid    = "AllowLambdaToReadFromAthenaS3Buckets"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = local.athena_s3_resources
  }

  # Grant Lambda function to write to AWS Kinesis
  statement {
    sid    = "AllowLambdaToWriteToKinesis"
    effect = "Allow"
    actions = [
      "kinesis:PutRecord*",
      "kinesis:ListStreams",
      "kinesis:DescribeStream",
    ]
    resources = [
      "arn:aws:kinesis:${var.aws_region}:${var.aws_account_id}:stream/${var.destination_kinesis_stream}",
    ]
  }
}

#
# IAM Roles and Permissions for StepFunction -> Lambda
#

# Setup the IAM Role for the Step Functions
resource "aws_iam_role" "iam_for_step_functions" {
  name               = "${var.prefix}_streamquery_state_machines"
  assume_role_policy = data.aws_iam_policy_document.iam_step_function_assume_role.json
}

# Only allow Step Functions to assume this role
data "aws_iam_policy_document" "iam_step_function_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "states.${var.aws_region}.amazonaws.com",
      ]
    }
  }
}

# Attach an additional policy to the IAM Role
resource "aws_iam_role_policy" "stepfunction_permissions" {
  name   = "${var.prefix}_streamquery_state_machine_permissions"
  role   = aws_iam_role.iam_for_step_functions.id
  policy = data.aws_iam_policy_document.stepfunction_permissions.json
}

# Permission for StepFunctions to invoke the Lambda function
data "aws_iam_policy_document" "stepfunction_permissions" {
  # Grant Step Function permission to invoke the Lambda
  statement {
    sid    = "AllowStateMachineToInvokeLambdaFunction"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
    ]
    resources = [
      "${module.streamquery_lambda.function_arn}:*",
    ]
  }
}

#
# IAM Roles and Permissions for CloudWatch -> Step Functions
#

# Setup the IAM Role
resource "aws_iam_role" "iam_for_cloudwatch_schedule" {
  name               = "${var.prefix}_streamquery_cloudwatch_schedule"
  assume_role_policy = data.aws_iam_policy_document.iam_cloudwatch_assume_role.json
}

# Only allow cloudwatch to assume this role
data "aws_iam_policy_document" "iam_cloudwatch_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "events.amazonaws.com",
      ]
    }
  }
}

# Attach additional permissions to the IAM Role
resource "aws_iam_role_policy" "cloudwatch_schedule_permissions" {
  name   = "${var.prefix}_streamquery_cloudwatch_schedule_permissions"
  role   = aws_iam_role.iam_for_cloudwatch_schedule.id
  policy = data.aws_iam_policy_document.cloudwatch_schedule_permission.json
}

# Permission to execute states:StartExecution
data "aws_iam_policy_document" "cloudwatch_schedule_permission" {
  statement {
    sid = "AllowCloudWatchScheduleToStartStepFunction"
    actions = [
      "states:StartExecution",
    ]
    resources = [
      aws_sfn_state_machine.state_machine.id,
    ]
  }
}

locals {
  # A list of all S3 bucket ARNs and ARN/*'s that the target Athena is built over
  athena_s3_resources = concat(
    formatlist("arn:aws:s3:::%s", var.athena_s3_buckets),
    formatlist("arn:aws:s3:::%s/*", var.athena_s3_buckets),
  )

  # A list of all glue ARNs that the Athena is built over
  athena_glue_resources = [
    "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:catalog",
    "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:database/${var.athena_database}",
    "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:table/${var.athena_database}/*",
  ]
}

