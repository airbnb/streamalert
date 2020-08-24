resource "aws_flow_log" "vpc_flow_log" {
  count                = length(var.vpcs)
  vpc_id               = element(var.vpcs, count.index)
  log_destination      = aws_cloudwatch_log_group.flow_log_group.arn
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.flow_log_role.arn
  traffic_type         = "ALL"
}

resource "aws_flow_log" "subnet_flow_log" {
  count                = length(var.subnets)
  subnet_id            = element(var.subnets, count.index)
  log_destination      = aws_cloudwatch_log_group.flow_log_group.arn
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.flow_log_role.arn
  traffic_type         = "ALL"
}

resource "aws_flow_log" "eni_flow_log" {
  count                = length(var.enis)
  eni_id               = element(var.enis, count.index)
  log_destination      = aws_cloudwatch_log_group.flow_log_group.arn
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.flow_log_role.arn
  traffic_type         = "ALL"
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "${var.prefix}_${var.cluster}_streamalert_flow_logs"
  retention_in_days = var.log_retention

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

resource "aws_cloudwatch_log_subscription_filter" "flow_logs" {
  name            = "${aws_cloudwatch_log_group.flow_log_group.name}_to_kinesis"
  log_group_name  = aws_cloudwatch_log_group.flow_log_group.name
  filter_pattern  = var.flow_log_filter
  destination_arn = var.cloudwatch_logs_destination_arn
}
