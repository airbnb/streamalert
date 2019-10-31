// CloudWatch metric alarm for a given metric
resource "aws_cloudwatch_metric_alarm" "cloudwatch_metric_alarms" {
  alarm_name          = var.alarm_name
  alarm_description   = var.alarm_description
  comparison_operator = var.comparison_operator
  evaluation_periods  = var.evaluation_periods
  metric_name         = var.metric_name
  period              = var.period
  statistic           = var.statistic
  threshold           = var.threshold
  alarm_actions       = [var.sns_topic_arn]

  namespace = "StreamAlert"

  tags = {
    Name = "StreamAlert"
  }
}
