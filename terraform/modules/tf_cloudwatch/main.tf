provider "aws" {
  region = "${var.region}"
}

# CloudWatch Logs Destination
# Sends logs to the default Kinesis stream for this cluster
resource "aws_cloudwatch_log_destination" "cloudwatch_kinesis" {
  name       = "${var.prefix}_${var.cluster}_streamalert_cloudwatch_to_kinesis"
  role_arn   = "${aws_iam_role.cloudwatch_subscription_role.arn}"
  target_arn = "${var.kinesis_stream_arn}"
}
