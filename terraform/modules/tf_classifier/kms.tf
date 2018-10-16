// KMS key: Server-Side Encryption for Classifier SQS
resource "aws_kms_key" "sse" {
  description         = "Classifier SQS server-side encryption"
  enable_key_rotation = true

  policy = "${data.aws_iam_policy_document.kms_sse_allow_lambda.json}"

  tags {
    Name = "StreamAlert"
  }
}

resource "aws_kms_alias" "sse" {
  name          = "alias/classifier_sqs_sse"
  target_key_id = "${aws_kms_key.sse.key_id}"
}
