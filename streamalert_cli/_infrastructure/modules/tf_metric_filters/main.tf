// CloudWatch metric filters for the specified log group
resource "aws_cloudwatch_log_metric_filter" "cloudwatch_metric_filters" {
  name           = var.metric_name
  pattern        = var.metric_pattern
  log_group_name = var.log_group_name

  metric_transformation {
    name          = var.metric_name
    value         = var.metric_value
    default_value = var.metric_default_value

    namespace = "StreamAlert"
  }
}
