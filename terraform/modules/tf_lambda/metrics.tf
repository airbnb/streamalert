resource "aws_cloudwatch_metric_alarm" "lambda_invocation_errors" {
  count               = "${var.enabled}"
  alarm_name          = "${var.function_name}_invocation_errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "${var.errors_alarm_threshold}"
  evaluation_periods  = "${var.errors_alarm_evaluation_periods}"
  period              = "${var.errors_alarm_period_secs}"
  alarm_description   = "StreamAlert Lambda Invocation Errors: ${var.function_name}"
  alarm_actions       = "${var.alarm_actions}"

  dimensions {
    FunctionName = "${var.function_name}"
    Resource     = "${var.function_name}:production"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count               = "${var.enabled}"
  alarm_name          = "${var.function_name}_throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "${var.throttles_alarm_threshold}"
  evaluation_periods  = "${var.throttles_alarm_evaluation_periods}"
  period              = "${var.throttles_alarm_period_secs}"
  alarm_description   = "StreamAlert Lambda Throttles: ${var.function_name}"
  alarm_actions       = "${var.alarm_actions}"

  dimensions {
    FunctionName = "${var.function_name}"
    Resource     = "${var.function_name}:production"
  }
}

// Lambda: IteratorAge
resource "aws_cloudwatch_metric_alarm" "streamalert_lambda_iterator_age" {
  count               = "${min(var.enabled, var.enable_iterator_age_alarm)}"
  alarm_name          = "${var.function_name}_iterator_age"
  namespace           = "AWS/Lambda"
  metric_name         = "IteratorAge"
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "${var.iterator_age_alarm_threshold}"
  evaluation_periods  = "${var.iterator_age_alarm_evaluation_periods}"
  period              = "${var.iterator_age_alarm_period_secs}"
  alarm_description   = "StreamAlert Lambda High Iterator Age: ${var.function_name}"
  alarm_actions       = "${var.alarm_actions}"

  dimensions {
    FunctionName = "${var.function_name}"
    Resource     = "${var.function_name}:production"
  }
}
