// SQS Queue: Send logs from the Classifier to the SQS queue
resource "aws_sqs_queue" "classifier_queue" {
  name = "${var.use_prefix ? "${var.prefix}_" : ""}streamalert_classified_logs"

  # The amount of time messages are hidden after being received from a consumer
  # Default this to 2 seconds longer than the maximum AWS Lambda duration
  visibility_timeout_seconds = var.rules_engine_timeout + 2

  # Enable queue encryption of messages in the queue
  kms_master_key_id = aws_kms_key.sqs_sse.arn

  tags = {
    Name = "StreamAlert"
  }
}

// SQS Queue Policy: Allow the Classifiers to send messages to SQS
resource "aws_sqs_queue_policy" "classifier_queue" {
  queue_url = aws_sqs_queue.classifier_queue.id
  policy    = data.aws_iam_policy_document.classifier_queue.json
}

// IAM Policy Doc: Allow Classifiers to send messages to SQS
data "aws_iam_policy_document" "classifier_queue" {
  statement {
    effect = "Allow"
    sid    = "AllowPublishToQueue"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.classifier_queue.arn]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"

      values = [
        "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_*_streamalert_classifier",
      ]
    }
  }
}

