// Permissions specific to the alert processor: decrypting secrets, sending alerts to outputs

locals {
  firehose_arn_prefix = "arn:aws:firehose:${var.region}:${var.account_id}"
  lambda_arn_prefix   = "arn:aws:lambda:${var.region}:${var.account_id}:function"
}

// Allow the Alert Processor to retrieve and decrypt output secrets
resource "aws_iam_role_policy" "output_secrets" {
  name   = "DecryptOutputSecrets"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.output_secrets.json}"
}

data "aws_iam_policy_document" "output_secrets" {
  // Allow decrypting output secrets
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = ["${var.kms_key_arn}"]
  }

  // Allow retrieving encrypted output secrets
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.prefix}.streamalert.secrets/*"]
  }
}

// Allow the Alert Processor to send to default firehose and S3 outputs
resource "aws_iam_role_policy" "default_outputs" {
  name   = "SinkToDefaultOutputs"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.default_outputs.json}"
}

data "aws_iam_policy_document" "default_outputs" {
  // Allow sending alerts to default firehose output
  statement {
    effect    = "Allow"
    actions   = ["firehose:Put*"]
    resources = ["${local.firehose_arn_prefix}:deliverystream/${var.prefix}_streamalert_alert_delivery"]
  }

  // Allow saving alerts to the default .streamalerts bucket
  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      "arn:aws:s3:::${var.prefix}.streamalerts",
      "arn:aws:s3:::${var.prefix}.streamalerts/*",
    ]
  }
}

// Allow the Alert Processor to invoke the configured output Lambda functions
resource "aws_iam_role_policy" "invoke_lambda_outputs" {
  count  = "${length(var.output_lambda_functions)}"
  name   = "LambdaInvoke_${element(var.output_lambda_functions, count.index)}"
  role   = "${var.role_id}"
  policy = "${element(data.aws_iam_policy_document.invoke_lambda_outputs.*.json, count.index)}"
}

data "aws_iam_policy_document" "invoke_lambda_outputs" {
  count = "${length(var.output_lambda_functions)}"

  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["${local.lambda_arn_prefix}:${element(var.output_lambda_functions, count.index)}"]
  }
}

// Allow the Alert Processor to write alerts to the configured output S3 buckets
resource "aws_iam_role_policy" "write_to_s3_outputs" {
  count  = "${length(var.output_s3_buckets)}"
  name   = "S3PutObject_${element(var.output_s3_buckets, count.index)}"
  role   = "${var.role_id}"
  policy = "${element(data.aws_iam_policy_document.write_to_s3_outputs.*.json, count.index)}"
}

data "aws_iam_policy_document" "write_to_s3_outputs" {
  count = "${length(var.output_lambda_functions)}"

  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      "arn:aws:s3:::${element(var.output_s3_buckets, count.index)}",
      "arn:aws:s3:::${element(var.output_s3_buckets, count.index)}/*",
    ]
  }
}
