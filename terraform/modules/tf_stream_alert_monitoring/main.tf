// Setup Cloudwatch alarms for all Lambda function aliases (environments)
// Send alerts to given SNS topics.

// Lambda: Invocation Errors
resource "aws_cloudwatch_metric_alarm" "streamalert_lambda_invocation_errors" {
  count               = "${length(var.lambda_functions)}"
  alarm_name          = "${element(var.lambda_functions, count.index)}_invocation_errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
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

// Lambda: Throttles
resource "aws_cloudwatch_metric_alarm" "streamalert_lambda_throttles" {
  count               = "${length(var.lambda_functions)}"
  alarm_name          = "${element(var.lambda_functions, count.index)}_throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "0"
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Lambda Throttles: ${element(var.lambda_functions, count.index)}"
  alarm_actions       = ["${var.sns_topic_arn}"]

  dimensions {
    FunctionName = "${element(var.lambda_functions, count.index)}"
    Resource     = "${element(var.lambda_functions, count.index)}:production"
  }
}

// Lambda: IteratorAge
resource "aws_cloudwatch_metric_alarm" "streamalert_lambda_iterator_age" {
  count               = "${length(var.lambda_functions)}"
  alarm_name          = "${element(var.lambda_functions, count.index)}_iterator_age"
  namespace           = "AWS/Lambda"
  metric_name         = "IteratorAge"
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "43000000"
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Lambda High Iterator Age: ${element(var.lambda_functions, count.index)}"
  alarm_actions       = ["${var.sns_topic_arn}"]

  dimensions {
    FunctionName = "${element(var.lambda_functions, count.index)}"
    Resource     = "${element(var.lambda_functions, count.index)}:production"
  }
}

// Kinesis: Iterator Age
resource "aws_cloudwatch_metric_alarm" "streamalert_kinesis_iterator_age" {
  alarm_name          = "${var.kinesis_stream}_high_iterator_age"
  namespace           = "AWS/Kinesis"
  metric_name         = "GetRecords.IteratorAgeMilliseconds"
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "43000000"                                                     // 12 hours
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Kinesis High Iterator Age: ${var.kinesis_stream}"
  alarm_actions       = ["${var.sns_topic_arn}"]

  dimensions {
    StreamName = "${var.kinesis_stream}"
  }
}

// Kinesis: Write Throughput Exceeded
resource "aws_cloudwatch_metric_alarm" "streamalert_kinesis_write_exceeded" {
  alarm_name          = "${var.kinesis_stream}_write_exceeded"
  namespace           = "AWS/Kinesis"
  metric_name         = "WriteProvisionedThroughputExceeded"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = "0"
  evaluation_periods  = "1"
  period              = "300"
  alarm_description   = "StreamAlert Kinesis Write Throughput Exceeded: ${var.kinesis_stream}"
  alarm_actions       = ["${var.sns_topic_arn}"]

  dimensions {
    StreamName = "${var.kinesis_stream}"
  }
}
