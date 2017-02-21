// Allow flow logs to write to CloudWatch
// http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html#flow-logs-iam

resource "aws_iam_role" "flow_log_role" {
  name = "flow_log_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
} 
EOF
}

resource "aws_iam_role_policy" "flow_log_write" {
  name = "write_to_cloudwatch"
  role = "${aws_iam_role.flow_log_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}   
EOF
}

// Allow log subscription to write to Kinesis Stream
// http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html

resource "aws_iam_role" "flow_log_subscription_role" {
  name = "flow_log_subscription_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.${var.region}.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
} 
EOF
}

resource "aws_iam_role_policy" "flow_logs_kinesis_wo" {
  name = "write_flow_logs_to_kinesis"
  role = "${aws_iam_role.flow_log_subscription_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement" : [
    {
      "Action": [
        "kinesis:PutRecord*",
        "kinesis:DescribeStream",
        "kinesis:ListStreams"
      ],
      "Effect": "Allow",
      "Resource": [
        "${var.destination_stream_arn}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "${aws_iam_role.flow_log_subscription_role.arn}"
    }
  ]
}
EOF
}
