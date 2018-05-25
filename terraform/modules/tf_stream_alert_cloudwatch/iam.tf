# IAM Role: Allows CloudWatch Logs to put data into
# this cluster's default Kinesis stream
resource "aws_iam_role" "cloudwatch_subscription_role" {
  name = "stream_alert_${var.cluster}_cw_sub_role_${var.region}"

  assume_role_policy = "${data.aws_iam_policy_document.cloudwatch_logs_assume_role_policy.json}"
}

// IAM Policy Document: AssumeRole for CloudWatch Logs
data "aws_iam_policy_document" "cloudwatch_logs_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
  }
}

// IAM Policy: Write to Kinesis
resource "aws_iam_role_policy" "cloudwatch_kinesis_wo" {
  name = "WriteCWLogsToKinesis"
  role = "${aws_iam_role.cloudwatch_subscription_role.id}"

  policy = "${data.aws_iam_policy_document.cloudwatch_put_kinesis_events.json}"
}

// IAM Policy Document: Write to Kinesis
data "aws_iam_policy_document" "cloudwatch_put_kinesis_events" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:PutRecord",
    ]

    resources = [
      "${var.kinesis_stream_arn}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "${aws_iam_role.cloudwatch_subscription_role.arn}",
    ]
  }
}

# IAM Policy: Access policy to allow writing CloudWatch logs cross-account
resource "aws_cloudwatch_log_destination_policy" "cloudwatch_kinesis" {
  count            = "${length(var.cross_account_ids) > 0 ? 1 : 0}"
  destination_name = "${aws_cloudwatch_log_destination.cloudwatch_kinesis.name}"
  access_policy    = "${data.aws_iam_policy_document.cross_account_destination_policy.json}"
}

// IAM Policy Document: Allow Cross Account CloudWatch logs subscription
data "aws_iam_policy_document" "cross_account_destination_policy" {
  count = "${length(var.cross_account_ids) > 0 ? 1 : 0}"

  statement {
    effect = "Allow"

    principals = {
      type = "AWS"

      identifiers = [
        "${var.cross_account_ids}",
      ]
    }

    actions = [
      "logs:PutSubscriptionFilter",
    ]

    resources = [
      "${aws_cloudwatch_log_destination.cloudwatch_kinesis.arn}",
    ]
  }
}
