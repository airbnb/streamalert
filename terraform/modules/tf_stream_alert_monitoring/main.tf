// Setup Cloudwatch alarms for all Lambda function aliases (environments)
// Send alerts to given SNS topics.
resource "aws_cloudwatch_metric_alarm" "stream_alert_invocation_errors" {
  count               = "${length(var.environments)}"
  alarm_name          = "${var.lambda_function_name}_invocation_errors_${var.environments["${count.index}"]}"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Average"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "0"
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Lambda Invocation Errors: ${var.environments["${count.index}"]}"
  alarm_actions       = ["${var.sns_topic_arns}"]

  dimensions {
    FunctionName = "${var.lambda_function_name}"
    Resource     = "${var.lambda_function_name}:${var.environments["${count.index}"]}"
  }
}
