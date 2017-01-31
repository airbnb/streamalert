resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket${title(replace(var.s3_bucket_id, ".", ""))}"
  action        = "lambda:InvokeFunction"
  function_name = "${var.lambda_function_arn}"
  principal     = "s3.amazonaws.com"
  source_arn    = "${var.s3_bucket_arn}"
  qualifier     = "production"
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "${var.s3_bucket_id}"

  lambda_function {
    lambda_function_arn = "${var.lambda_function_arn}:production"
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_iam_role_policy" "lambda_s3_permission" {
  name = "${var.lambda_function_name}_to_${var.s3_bucket_id}"
  role = "${var.lambda_role_id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:List*",
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "${var.s3_bucket_arn}",
        "${var.s3_bucket_arn}/*"
      ]
    }
  ]
}
EOF
}
