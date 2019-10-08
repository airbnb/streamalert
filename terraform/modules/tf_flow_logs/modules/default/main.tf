// Note: When creating cross-account log destinations, the destination must
//       be in the same AWS region as the log group that is sending it data.
//       However, the AWS resource that the destination points to can be
//       located in a different region.
// Source: http://amzn.to/2zF7CS0
resource "aws_cloudwatch_log_destination" "kinesis" {
  name       = "${var.prefix}_${var.cluster}_streamalert_flow_log_destination"
  role_arn   = "${aws_iam_role.flow_log_subscription_role.arn}"
  target_arn = "${var.destination_stream_arn}"
}

resource "aws_cloudwatch_log_destination_policy" "kinesis" {
  destination_name = "${aws_cloudwatch_log_destination.kinesis.name}"
  access_policy    = "${data.aws_iam_policy_document.cloudwatch_logs_destination_policy.json}"
}
