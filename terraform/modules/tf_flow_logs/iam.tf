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

// Allow flow logs to write to CloudWatch
// http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html#flow-logs-iam
// IAM Role: Clustered VPC Flow Log
resource "aws_iam_role" "flow_log_role" {
  name               = "${var.prefix}_${var.cluster}_flow_log_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.flow_log_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// IAM Policy: CloudWatch Put Events
resource "aws_iam_role_policy" "flow_logs_write_to_cloudwatch_logs" {
  name   = "CloudWatchPutEvents"
  role   = aws_iam_role.flow_log_role.id
  policy = data.aws_iam_policy_document.flow_logs_write_to_cloudwatch_logs.json
}

// IAM Policy Doc: CloudWatch Put Events
data "aws_iam_policy_document" "flow_logs_write_to_cloudwatch_logs" {
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

