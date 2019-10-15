// Lambda Permission: Allow S3 Event Notifications to invoke Lambda
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "InvokeFromS3Bucket_${var.notification_id}"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.bucket_id}"
  qualifier     = var.lambda_function_alias
}

// S3 Bucket Notification: Invoke the StreamAlert Classifier
resource "aws_s3_bucket_notification" "bucket_notification" {
  count  = var.enable_events ? 1 : 0
  bucket = var.bucket_id

  lambda_function {
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = var.filter_prefix
    filter_suffix       = var.filter_suffix
    id                  = "notify_${var.notification_id}"
    lambda_function_arn = var.lambda_function_alias_arn
  }
}

// IAM Policy: Allow Lambda to GetObjects from S3
resource "aws_iam_role_policy" "lambda_s3_permission" {
  name   = "S3GetObjects_${var.notification_id}"
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
      "arn:aws:s3:::${var.bucket_id}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:Get*",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_id}/*",
    ]
  }
}
