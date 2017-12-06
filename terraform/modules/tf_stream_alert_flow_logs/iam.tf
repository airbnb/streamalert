// Allow flow logs to write to CloudWatch
// http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html#flow-logs-iam
// IAM Role: Clustered VPC Flow Log
resource "aws_iam_role" "flow_log_role" {
  name = "stream_alert_${var.cluster}_flow_log_role"

  assume_role_policy = "${data.aws_iam_policy_document.flow_log_assume_role_policy.json}"
}

// IAM Policy Doc: AssumeRole for VPC Flow Logs
data "aws_iam_policy_document" "flow_log_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

// IAM Policy: CloudWatch Put Events
resource "aws_iam_role_policy" "flow_log_write" {
  name = "CloudWatchPutEvents"
  role = "${aws_iam_role.flow_log_role.id}"

  policy = "${data.aws_iam_policy_document.flow_log_put_cloudwatch_logs.json}"
}

// IAM Policy Doc: CloudWatch Put Events
data "aws_iam_policy_document" "flow_log_put_cloudwatch_logs" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]

    resources = [
      "*",
    ]
  }
}

// Allow log subscription to write to Kinesis Stream
// http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html
// IAM Role: Clustered CloudWatch Flow Log Role
resource "aws_iam_role" "flow_log_subscription_role" {
  name = "stream_alert_${var.cluster}_flow_log_subscription_role"

  assume_role_policy = "${data.aws_iam_policy_document.cloudwatch_logs_assume_role_policy.json}"
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
resource "aws_iam_role_policy" "flow_logs_kinesis_wo" {
  name = "write_flow_logs_to_kinesis"
  role = "${aws_iam_role.flow_log_subscription_role.id}"

  policy = "${data.aws_iam_policy_document.flow_logs_put_kinesis_events.json}"
}

// IAM Policy Doc: Write to Kinesis
data "aws_iam_policy_document" "flow_logs_put_kinesis_events" {
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

// IAM Policy Doc: Allow Cross Account Flow Logs
data "aws_iam_policy_document" "cross_account_destination_policy" {
  count = "${length(var.cross_account_ids) > 0 ? 1 : 0}"

  statement {
    sid    = "CrossAccountDestinationPolicy"
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
      "${aws_cloudwatch_log_destination.kinesis.arn}",
    ]
  }
}
