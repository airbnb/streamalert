// IAM Role Policy: Allow the Classifier to send data to Firehose
resource "aws_iam_role_policy" "classifier_firehose" {
  name = "FirehoseWriteData"
  role = "${var.function_role_id}"

  policy = "${data.aws_iam_policy_document.classifier_firehose.json}"
}

// IAM Policy Doc: Allow the Classifier to PutRecord* on any StreamAlert Data Firehose
data "aws_iam_policy_document" "classifier_firehose" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:PutRecord*",
      "firehose:DescribeDeliveryStream",
      "firehose:ListDeliveryStreams",
    ]

    resources = [
      "arn:aws:firehose:${var.region}:${var.account_id}:deliverystream/streamalert_data_*",
    ]
  }
}

// Allow Lambda to use the SSE key when publishing events to SQS
data "aws_iam_policy_document" "kms_sse_allow_lambda" {
  statement {
    sid    = "AllowLambdaToUseKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = ["*"]
  }
}

// IAM Policy Doc: Allow configured data buckets to send SQS messages
data "aws_iam_policy_document" "classifier_queue" {
  statement {
    effect = "Allow"

    actions = [
      "sqs:SendMessage",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      "${aws_sqs_queue.classifier_queue.arn}",
    ]
  }
}

// IAM Role Policy: Allow Classifier to read, decrypt, and delete SQS messages
resource "aws_iam_role_policy" "sqs" {
  name = "SQSReadDecryptDeleteMessages"
  role = "${var.function_role_id}"

  policy = "${data.aws_iam_policy_document.sqs.json}"
}

// IAM Policy Doc: Allow Classifier to read, decrypt, and delete SQS messages
data "aws_iam_policy_document" "sqs" {
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      "${aws_kms_key.sse.arn}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "sqs:ListQueues",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "sqs:DeleteMessage",
      "sqs:DeleteMessageBatch",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
    ]

    resources = [
      "${aws_sqs_queue.classifier_queue.arn}",
    ]
  }
}
