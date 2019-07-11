// SQS Queue: Send logs from the Classifier to the SQS queue

# FIXME (derek.wang) This old queue has an un-prefixed name and is deprecated
# We CANNOT change the resource id as Terraform uses this id to determine whether or not to
# Destroy it. If we change it to something like "classifier_queue_OLD" Terraform will destroy
# the original and create anew, which is not what we want.
resource "aws_sqs_queue" "classifier_queue" {
  name = "streamalert_classified_logs"

  # The amount of time messages are hidden after being received from a consumer
  # Default this to 2 seconds longer than the maximum AWS Lambda duration
  visibility_timeout_seconds = "${var.rules_engine_timeout + 2}"

  # Enable queue encryption of messages in the queue
  kms_master_key_id = "${aws_kms_key.sqs_sse.arn}"

  tags {
    Name = "StreamAlert"
  }
}

resource "aws_sqs_queue" "classifier_destination_queue" {
  name = "${var.prefix}_streamalert_classified_logs"

  # The amount of time messages are hidden after being received from a consumer
  # Default this to 2 seconds longer than the maximum AWS Lambda duration
  visibility_timeout_seconds = "${var.rules_engine_timeout + 2}"

  # Enable queue encryption of messages in the queue
  kms_master_key_id = "${aws_kms_key.sqs_sse.arn}"

  tags {
    Name = "StreamAlert"
  }
}

// SQS Queue Policy: Allow the Classifiers to send messages to SQS
# FIXME (derek.wang) get rid of this old one later.
resource "aws_sqs_queue_policy" "classifier_queue" {
  queue_url = "${aws_sqs_queue.classifier_queue.id}"
  policy    = "${data.aws_iam_policy_document.classifier_queue.json}"
}

resource "aws_sqs_queue_policy" "classifier_destination_queue" {
  queue_url = "${aws_sqs_queue.classifier_destination_queue.id}"
  policy    = "${data.aws_iam_policy_document.classifier_destination_queue.json}"
}

// IAM Policy Doc: Allow Classifiers to send messages to SQS

# FIXME (derek.wang) Delete this post-migration
data "aws_iam_policy_document" "classifier_queue" {
  statement {
    effect = "Allow"
    sid    = "AllowPublishToQueue"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    # FIXME (derek.wang) The policy document is duplicated below because for some reason AWS
    #       Forces there to only be 1 resource in a SQS Policy document.
    resources = ["${aws_sqs_queue.classifier_queue.arn}"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"

      values = [
        "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_streamalert_classifier_*",
      ]
    }
  }
}

data "aws_iam_policy_document" "classifier_destination_queue" {
  statement {
    effect = "Allow"
    sid    = "AllowPublishToQueue"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    resources = ["${aws_sqs_queue.classifier_destination_queue.arn}"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"

      values = [
        "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_streamalert_classifier_*",
      ]
    }
  }
}
