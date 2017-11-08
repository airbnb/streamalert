// CloudWatch metric filters for the rule processor
// The split list is made up of: <filter_name>, <filter_pattern>, <value>
resource "aws_cloudwatch_log_metric_filter" "rule_processor_cw_metric_filters" {
  count          = "${length(var.rule_processor_metric_filters)}"
  name           = "${element(split(",", var.rule_processor_metric_filters[count.index]), 0)}"
  pattern        = "${element(split(",", var.rule_processor_metric_filters[count.index]), 1)}"
  log_group_name = "${aws_cloudwatch_log_group.rule_processor.name}"

  metric_transformation {
    name      = "${element(split(",", var.rule_processor_metric_filters[count.index]), 0)}"
    namespace = "${var.namespace}"
    value     = "${element(split(",", var.rule_processor_metric_filters[count.index]), 2)}"
  }
}

// CloudWatch metric filters for the alert processor
// The split list is made up of: <filter_name>, <filter_pattern>, <value>
resource "aws_cloudwatch_log_metric_filter" "alert_processor_cw_metric_filters" {
  count          = "${length(var.alert_processor_metric_filters)}"
  name           = "${element(split(",", var.alert_processor_metric_filters[count.index]), 0)}"
  pattern        = "${element(split(",", var.alert_processor_metric_filters[count.index]), 1)}"
  log_group_name = "${aws_cloudwatch_log_group.alert_processor.name}"

  metric_transformation {
    name      = "${element(split(",", var.alert_processor_metric_filters[count.index]), 0)}"
    namespace = "${var.namespace}"
    value     = "${element(split(",", var.alert_processor_metric_filters[count.index]), 2)}"
  }
}

// CloudWatch metric alarms that are created per-cluster
// The split list is our way around poor tf support for lists of maps and is made up of:
// <alarm_name>, <alarm_description>, <comparison_operator>, <evaluation_periods>,
// <metric>, <period>, <statistic>, <threshold>
// TODO: update this logic to simply use a variable that is a list of maps once Terraform fixes this
resource "aws_cloudwatch_metric_alarm" "cw_metric_alarms" {
  count               = "${length(var.metric_alarms)}"
  alarm_name          = "${element(split(",", var.metric_alarms[count.index]), 0)}"
  alarm_description   = "${element(split(",", var.metric_alarms[count.index]), 1)}"
  comparison_operator = "${element(split(",", var.metric_alarms[count.index]), 2)}"
  evaluation_periods  = "${element(split(",", var.metric_alarms[count.index]), 3)}"
  metric_name         = "${element(split(",", var.metric_alarms[count.index]), 4)}"
  period              = "${element(split(",", var.metric_alarms[count.index]), 5)}"
  statistic           = "${element(split(",", var.metric_alarms[count.index]), 6)}"
  threshold           = "${element(split(",", var.metric_alarms[count.index]), 7)}"
  namespace           = "${var.namespace}"
  alarm_actions       = ["${var.sns_topic_arn}"]
}
