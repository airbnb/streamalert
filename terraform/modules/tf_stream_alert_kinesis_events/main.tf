// AWS Lambda Function Policy
resource "aws_iam_role_policy" "stream_alert_lambda_kinesis" {
  name = "stream_alert_lambda_kinesis_${var.role_policy_prefix}"
  role = "${var.lambda_role_id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kinesis:DescribeStream",
        "kinesis:GetRecords",
        "kinesis:GetShardIterator",
        "kinesis:ListStreams",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_lambda_event_source_mapping" "stream_alert_kinesis_production_event_mapping" {
  enabled           = "${var.lambda_production_enabled}"
  batch_size        = 100
  event_source_arn  = "${var.kinesis_stream_arn}"
  function_name     = "${var.lambda_function_arn}:production"
  starting_position = "TRIM_HORIZON"
}
