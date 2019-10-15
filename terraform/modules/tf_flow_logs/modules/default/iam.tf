// IAM Policy Doc: Allow Cross Account Flow Logs
data "aws_iam_policy_document" "cloudwatch_logs_destination_policy" {
  statement {
    sid    = "DestinationPolicy"
    effect = "Allow"

    principals = {
      type = "AWS"

      identifiers = [
        "${var.account_ids}",
      ]
    }

    actions = [
      "logs:PutSubscriptionFilter",
    ]

    resources = [
      "${aws_cloudwatch_log_destination.kinesis.arn}",
    ]
  }
}

// Allow log subscription to write to Kinesis Stream
// http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html
// IAM Role: Clustered CloudWatch Flow Log Role
resource "aws_iam_role" "flow_log_subscription_role" {
  name               = "${var.prefix}_${var.cluster}_flow_log_subscription_role"
  path               = "/streamalert/"
  assume_role_policy = "${data.aws_iam_policy_document.cloudwatch_logs_assume_role_policy.json}"

  tags {
    Name    = "StreamAlert"
    Cluster = "${var.cluster}"
  }
}

// IAM Policy Doc: AssumeRole for CloudWatch Logs
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
resource "aws_iam_role_policy" "flow_logs_write_to_kinesis" {
  name   = "WriteFlowLogsToKinesis"
  role   = "${aws_iam_role.flow_log_subscription_role.id}"
  policy = "${data.aws_iam_policy_document.flow_logs_write_to_kinesis.json}"
}

// IAM Policy Doc: Write to Kinesis
data "aws_iam_policy_document" "flow_logs_write_to_kinesis" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
      "kinesis:PutRecord*",
    ]

    resources = [
      "${var.destination_stream_arn}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "${aws_iam_role.flow_log_subscription_role.arn}",
    ]
  }
}
