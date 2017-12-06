provider "aws" {
  region = "${var.region}"
}

resource "aws_flow_log" "vpc_flow_log" {
  count          = "${length(var.vpcs)}"
  vpc_id         = "${element(var.vpcs, count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_flow_log" "subnet_flow_log" {
  count          = "${length(var.subnets)}"
  subnet_id      = "${element(var.subnets, count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_flow_log" "eni_flow_log" {
  count          = "${length(var.enis)}"
  eni_id         = "${element(var.enis, count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "${var.flow_log_group_name}"
  retention_in_days = "${var.log_retention}"
}

// Note: When creating cross-account log destinations,
//       the log group and the destination must be in the same AWS region.
//       However, the AWS resource that the destination points to can be 
//       located in a different region.
// Source: http://amzn.to/2zF7CS0
resource "aws_cloudwatch_log_destination" "kinesis" {
  name       = "stream_alert_${var.cluster}_log_destination"
  role_arn   = "${aws_iam_role.flow_log_subscription_role.arn}"
  target_arn = "${var.destination_stream_arn}"
}

resource "aws_cloudwatch_log_destination_policy" "kinesis" {
  count            = "${length(var.cross_account_ids) > 0 ? 1 : 0}"
  destination_name = "${aws_cloudwatch_log_destination.kinesis.name}"
  access_policy    = "${data.aws_iam_policy_document.cross_account_destination_policy.json}"
}

resource "aws_cloudwatch_log_subscription_filter" "flow_logs" {
  name            = "${aws_cloudwatch_log_group.flow_log_group.name}_to_kinesis"
  log_group_name  = "${aws_cloudwatch_log_group.flow_log_group.name}"
  filter_pattern  = "${var.flow_log_filter}"
  destination_arn = "${aws_cloudwatch_log_destination.kinesis.arn}"
  depends_on      = ["aws_cloudwatch_log_destination_policy.kinesis"]
}
