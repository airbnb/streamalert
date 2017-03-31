provider "aws" {
  region = "${var.region}"
}

resource "aws_flow_log" "vpc_flow_log" {
  count          = "${length(var.targets["vpcs"])}"
  vpc_id         = "${element(var.targets["vpcs"],count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_flow_log" "subnet_flow_log" {
  count          = "${length(var.targets["subnets"])}"
  subnet_id      = "${element(var.targets["subnets"],count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_flow_log" "eni_flow_log" {
  count          = "${length(var.targets["enis"])}"
  eni_id         = "${element(var.targets["enis"],count.index)}"
  log_group_name = "${aws_cloudwatch_log_group.flow_log_group.name}"
  iam_role_arn   = "${aws_iam_role.flow_log_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name = "${var.flow_log_group_name}"
}

resource "aws_cloudwatch_log_subscription_filter" "flow_logs" {
  name            = "${aws_cloudwatch_log_group.flow_log_group.name}_to_lambda"
  log_group_name  = "${aws_cloudwatch_log_group.flow_log_group.name}"
  filter_pattern  = "${var.flow_log_filter}"
  destination_arn = "${var.destination_stream_arn}"
  role_arn        = "${aws_iam_role.flow_log_subscription_role.arn}"
}
