// Setup Cloudwatch alarms for all Lambda function aliases (environments)
// Send alerts to given SNS topics.
resource "aws_cloudwatch_metric_alarm" "stream_alert_invocation_errors" {
  count               = "${length(var.lambda_functions)}"
  alarm_name          = "${element(var.lambda_functions, count.index)}_invocation_errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Average"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "0"
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Lambda Invocation Errors: ${element(var.lambda_functions, count.index)}"
  alarm_actions       = ["${var.sns_topic_arn}"]

  dimensions {
    FunctionName = "${element(var.lambda_functions, count.index)}"
    Resource     = "${element(var.lambda_functions, count.index)}:production"
  }
}
