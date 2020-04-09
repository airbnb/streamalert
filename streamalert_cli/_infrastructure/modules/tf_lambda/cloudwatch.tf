/* CloudWatch event rules, log group, and metric alarms */

// CloudWatch event to trigger Lambda on a regular schedule (if applicable)

resource "aws_cloudwatch_event_rule" "invocation_schedule" {
  count               = local.schedule_enabled ? 1 : 0
  name                = "${aws_lambda_function.function.function_name}_schedule"
  description         = "Invokes ${aws_lambda_function.function.function_name} at ${var.schedule_expression}"
  schedule_expression = var.schedule_expression

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "invoke_lambda" {
  count = local.schedule_enabled ? 1 : 0
  rule  = aws_cloudwatch_event_rule.invocation_schedule[0].name
  arn   = aws_lambda_alias.alias.arn
  input = jsonencode(var.lambda_input_event)
}

// CloudWatch log group with configurable retention, tagging, and metric filters

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.function.function_name}"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

// Generic CloudWatch metric alarms related to this function

resource "aws_cloudwatch_metric_alarm" "lambda_invocation_errors" {
  count               = var.errors_alarm_enabled ? 1 : 0
  alarm_name          = "${aws_lambda_function.function.function_name}_invocation_errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.errors_alarm_threshold
  evaluation_periods  = var.errors_alarm_evaluation_periods
  period              = var.errors_alarm_period_secs
  alarm_description   = "StreamAlert Lambda Invocation Errors: ${aws_lambda_function.function.function_name}"
  alarm_actions       = var.alarm_actions

  dimensions = {
    FunctionName = aws_lambda_function.function.function_name
    Resource     = "${aws_lambda_function.function.function_name}:${aws_lambda_alias.alias.name}"
  }

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count               = var.throttles_alarm_enabled ? 1 : 0
  alarm_name          = "${aws_lambda_function.function.function_name}_throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.throttles_alarm_threshold
  evaluation_periods  = var.throttles_alarm_evaluation_periods
  period              = var.throttles_alarm_period_secs
  alarm_description   = "StreamAlert Lambda Throttles: ${aws_lambda_function.function.function_name}"
  alarm_actions       = var.alarm_actions

  dimensions = {
    FunctionName = aws_lambda_function.function.function_name
    Resource     = "${aws_lambda_function.function.function_name}:${aws_lambda_alias.alias.name}"
  }

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "streamalert_lambda_iterator_age" {
  count               = var.iterator_age_alarm_enabled ? 1 : 0
  alarm_name          = "${aws_lambda_function.function.function_name}_iterator_age"
  namespace           = "AWS/Lambda"
  metric_name         = "IteratorAge"
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.iterator_age_alarm_threshold_ms
  evaluation_periods  = var.iterator_age_alarm_evaluation_periods
  period              = var.iterator_age_alarm_period_secs
  alarm_description   = "StreamAlert Lambda High Iterator Age: ${aws_lambda_function.function.function_name}"
  alarm_actions       = var.alarm_actions

  dimensions = {
    FunctionName = aws_lambda_function.function.function_name
    Resource     = "${aws_lambda_function.function.function_name}:${aws_lambda_alias.alias.name}"
  }

  tags = local.tags
}
