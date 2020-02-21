// Allow Lambda to use the SSE key when publishing events to SQS
data "aws_iam_policy_document" "kms_sse_allow" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

