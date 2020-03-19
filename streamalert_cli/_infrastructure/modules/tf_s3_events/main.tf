locals {
  sanitized_bucket_name = replace(var.bucket_name, "/[^a-zA-Z0-9_-]/", "_")
}

// Lambda Permission: Allow S3 Event Notifications to invoke Lambda
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "InvokeFromS3Bucket_${local.sanitized_bucket_name}"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.bucket_name}"
  qualifier     = var.lambda_function_alias
}

// This hack ensures that the lambda_function block is still created
// even if no filters are provided
locals {
  filters = coalescelist(var.filters, [{}])
}

// S3 Bucket Notification: Invoke the StreamAlert Classifier
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = var.bucket_name

  dynamic "lambda_function" {
    for_each = local.filters

    content {
      events              = ["s3:ObjectCreated:*"]
      filter_prefix       = lookup(lambda_function.value, "filter_prefix", "") // use lookup since this is optional
      filter_suffix       = lookup(lambda_function.value, "filter_suffix", "") // use lookup since this is optional
      lambda_function_arn = var.lambda_function_alias_arn
    }
  }
}

// IAM Policy: Allow Lambda to GetObjects from S3
resource "aws_iam_role_policy" "lambda_s3_permission" {
  name   = "S3GetObjects_${var.bucket_name}"
  role   = var.lambda_role_id
  policy = data.aws_iam_policy_document.s3_read_only.json
}

// IAM Policy Doc: S3 Get Object
data "aws_iam_policy_document" "s3_read_only" {
  statement {
    effect = "Allow"

    actions = [
      "s3:List*",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_name}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:Get*",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_name}/*",
    ]
  }
}
