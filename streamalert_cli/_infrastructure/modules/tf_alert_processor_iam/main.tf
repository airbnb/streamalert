// Permissions specific to the alert processor: decrypting secrets, sending alerts to outputs

locals {
  dynamo_arn_prefix   = "arn:aws:dynamodb:${var.region}:${var.account_id}:table"
  firehose_arn_prefix = "arn:aws:firehose:${var.region}:${var.account_id}"
  lambda_arn_prefix   = "arn:aws:lambda:${var.region}:${var.account_id}:function"
  sns_arn_prefix      = "arn:aws:sns:${var.region}:${var.account_id}"
  sqs_arn_prefix      = "arn:aws:sqs:${var.region}:${var.account_id}"

  // Terraform is upset if you try to index into an empty list, even if the resource count = 0.
  // https://github.com/hashicorp/terraform/issues/11210
  // As a workaround, we append an unused dummy element to the output lists.

  lambda_outputs = concat(var.output_lambda_functions, ["unused"])
  s3_outputs     = concat(var.output_s3_buckets, ["unused"])
  sns_outputs    = concat(var.output_sns_topics, ["unused"])
  sqs_outputs    = concat(var.output_sqs_queues, ["unused"])
}

// Allow the Alert Processor to update the alerts table
resource "aws_iam_role_policy" "update_alerts_table" {
  name   = "UpdateAlertsTable"
  role   = var.role_id
  policy = data.aws_iam_policy_document.update_alerts_table.json
}

data "aws_iam_policy_document" "update_alerts_table" {
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]

    resources = ["${local.dynamo_arn_prefix}/${var.prefix}_streamalert_alerts"]
  }
}

// Allow the Alert Processor to retrieve and decrypt output secrets
resource "aws_iam_role_policy" "output_secrets" {
  name   = "DecryptOutputSecrets"
  role   = var.role_id
  policy = data.aws_iam_policy_document.output_secrets.json
}

data "aws_iam_policy_document" "output_secrets" {
  // Allow decrypting output secrets
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [var.kms_key_arn, var.sse_kms_key_arn]
  }

  # FIXME (Ryxias) DRY out this SSM parameter name with what is configured in the SSMDriver
  # Allow retrieving encrypted output secrets
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.prefix}/streamalert/outputs/*"]
  }
}


// Allow the Alert Processor to send to default firehose and S3 outputs
resource "aws_iam_role_policy" "default_outputs" {
  name   = "DefaultOutputs"
  role   = var.role_id
  policy = data.aws_iam_policy_document.default_outputs.json
}

data "aws_iam_policy_document" "default_outputs" {
  // Allow sending alerts to default firehose output
  statement {
    effect    = "Allow"
    actions   = ["firehose:Put*"]
    resources = ["${local.firehose_arn_prefix}:deliverystream/${var.prefix}_streamalert_alert_delivery"]
  }

  // Allow saving alerts to the default -streamalerts bucket
  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}-streamalerts",
      "arn:aws:s3:::${var.prefix}-streamalerts/*",
    ]
  }
}

// Allow the Alert Processor to invoke the configured output Lambda functions
resource "aws_iam_role_policy" "invoke_lambda_outputs" {
  count = length(var.output_lambda_functions)
  name  = "LambdaInvoke_${element(local.lambda_outputs, count.index)}"
  role  = var.role_id
  policy = element(
    data.aws_iam_policy_document.invoke_lambda_outputs.*.json,
    count.index,
  )
}

data "aws_iam_policy_document" "invoke_lambda_outputs" {
  count = length(var.output_lambda_functions)

  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["${local.lambda_arn_prefix}:${element(local.lambda_outputs, count.index)}"]
  }
}

// Allow the Alert Processor to write alerts to the configured output S3 buckets
resource "aws_iam_role_policy" "write_to_s3_outputs" {
  count = length(var.output_s3_buckets)
  name  = "S3PutObject_${element(local.s3_outputs, count.index)}"
  role  = var.role_id
  policy = element(
    data.aws_iam_policy_document.write_to_s3_outputs.*.json,
    count.index,
  )
}

data "aws_iam_policy_document" "write_to_s3_outputs" {
  count = length(var.output_s3_buckets)

  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      "arn:aws:s3:::${element(local.s3_outputs, count.index)}",
      "arn:aws:s3:::${element(local.s3_outputs, count.index)}/*",
    ]
  }
}

// Allow the Alert Processor to publish to the configured SNS topics
resource "aws_iam_role_policy" "publish_to_sns_topics" {
  count = length(var.output_sns_topics)
  name  = "SNSPublish_${element(local.sns_outputs, count.index)}"
  role  = var.role_id
  policy = element(
    data.aws_iam_policy_document.publish_to_sns_topics.*.json,
    count.index,
  )
}

data "aws_iam_policy_document" "publish_to_sns_topics" {
  count = length(var.output_sns_topics)

  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = ["${local.sns_arn_prefix}:${element(local.sns_outputs, count.index)}"]
  }
}

// Allow the Alert Processor to send to the configured SQS queues
resource "aws_iam_role_policy" "send_to_sqs_queues" {
  count = length(var.output_sqs_queues)
  name  = "SQSSend_${element(local.sqs_outputs, count.index)}"
  role  = var.role_id
  policy = element(
    data.aws_iam_policy_document.send_to_sqs_queues.*.json,
    count.index,
  )
}

data "aws_iam_policy_document" "send_to_sqs_queues" {
  count = length(var.output_sqs_queues)

  statement {
    effect = "Allow"

    actions = [
      "sqs:GetQueueUrl",
      "sqs:SendMessage*",
    ]

    resources = ["${local.sqs_arn_prefix}:${element(local.sqs_outputs, count.index)}"]
  }
}

// Allow the Alert Processor to use ses:SendRawEmail
resource "aws_iam_role_policy" "send_raw_emails" {
  name   = "SendRawEmails"
  role   = var.role_id
  policy = data.aws_iam_policy_document.send_raw_emails.json
}

data "aws_iam_policy_document" "send_raw_emails" {
  statement {
    effect = "Allow"

    actions = [
      "ses:SendRawEmail"
    ]

    // * because there isn't a way to state the emails or
    // domains before the user puts them in as a secret
    resources = ["*"]
  }
}
