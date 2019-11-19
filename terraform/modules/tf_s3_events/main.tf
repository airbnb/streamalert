// Lambda Permission: Allow S3 Event Notifications to invoke Lambda
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "${var.prefix}_${var.cluster}_InvokeFromS3Bucket_${var.bucket_name}"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.bucket_name}"
  qualifier     = var.lambda_function_alias
}

// S3 Bucket Notification: Invoke the StreamAlert Classifier
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = var.bucket_name

  dynamic "lambda_function" {
    for_each = var.filters

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
  name   = "${var.prefix}_${var.cluster}_S3GetObjects_${var.bucket_name}"
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
