// Allow log subscription to write to Kinesis Stream
// http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html
// IAM Role: Clustered CloudWatch Flow Log Role
resource "aws_iam_role" "subscription_role" {
  name               = "${var.prefix}_${var.cluster}_cloudwatch_logs_subscription_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_logs_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Policy Doc: AssumeRole for CloudWatch Logs from multiple regions
data "aws_iam_policy_document" "cloudwatch_logs_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = formatlist("logs.%s.amazonaws.com", var.regions)
    }
  }
}

// IAM Policy: CloudWatch Logs Write to Kinesis
resource "aws_iam_role_policy" "cloudwatch_logs_write_to_kinesis" {
  name   = "CloudWatchLogsWriteToKinesis"
  role   = aws_iam_role.subscription_role.id
  policy = data.aws_iam_policy_document.cloudwatch_logs_write_to_kinesis.json
}

// IAM Policy Doc: CloudWatch Logs Write to Kinesis
data "aws_iam_policy_document" "cloudwatch_logs_write_to_kinesis" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
      "kinesis:PutRecord*",
    ]

    resources = [
      var.destination_kinesis_stream_arn,
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      aws_iam_role.subscription_role.arn,
    ]
  }
}
