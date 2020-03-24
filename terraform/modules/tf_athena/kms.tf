// KMS key: Server-Side Encryption for SQS
resource "aws_kms_key" "sse" {
  description         = "Athena SQS server-side encryption"
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.kms_sse_allow_s3.json

  tags = {
    Name    = "StreamAlert"
    AltName = "Athena"
  }
}

resource "aws_kms_alias" "sse" {
  name          = "alias/${var.prefix}_streamalert_sqs_sse"
  target_key_id = aws_kms_key.sse.key_id
}
