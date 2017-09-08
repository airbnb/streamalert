// Lambda Function: Rule Processor
//    Matches rules against logs from Kinesis, S3, or SNS
resource "aws_lambda_function" "streamalert_rule_processor" {
  function_name = "${var.prefix}_${var.cluster}_streamalert_rule_processor"
  description   = "StreamAlert Rule Processor"
  runtime       = "python2.7"
  role          = "${aws_iam_role.streamalert_rule_processor_role.arn}"
  handler       = "${lookup(var.rule_processor_config, "handler")}"
  memory_size   = "${var.rule_processor_memory}"
  timeout       = "${var.rule_processor_timeout}"
  s3_bucket     = "${lookup(var.rule_processor_config, "source_bucket")}"
  s3_key        = "${lookup(var.rule_processor_config, "source_object_key")}"

  environment {
    variables = {
      CLUSTER        = "${var.cluster}"
      LOGGER_LEVEL   = "${var.rule_processor_log_level}"
      ENABLE_METRICS = "${var.rule_processor_enable_metrics}"
    }
  }

  tags {
    Name = "StreamAlert"
  }
}

// Lambda Alias: Rule Processor Production
resource "aws_lambda_alias" "rule_processor_production" {
  name             = "production"
  description      = "Production StreamAlert Rule Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_rule_processor.arn}"
  function_version = "${var.rule_processor_version}"
}

// Lambda Function: Alert Processor
//    Send alerts to declared outputs
//    VPC
resource "aws_lambda_function" "streamalert_alert_processor_vpc" {
  count         = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  function_name = "${var.prefix}_${var.cluster}_streamalert_alert_processor"
  description   = "StreamAlert Alert Processor"
  runtime       = "python2.7"
  role          = "${aws_iam_role.streamalert_alert_processor_role.arn}"
  handler       = "${lookup(var.alert_processor_config, "handler")}"
  memory_size   = "${var.alert_processor_memory}"
  timeout       = "${var.alert_processor_timeout}"
  s3_bucket     = "${lookup(var.alert_processor_config, "source_bucket")}"
  s3_key        = "${lookup(var.alert_processor_config, "source_object_key")}"

  environment {
    variables = {
      CLUSTER        = "${var.cluster}"
      LOGGER_LEVEL   = "${var.alert_processor_log_level}"
      ENABLE_METRICS = "${var.alert_processor_enable_metrics}"
    }
  }

  vpc_config {
    subnet_ids         = "${var.alert_processor_vpc_subnet_ids}"
    security_group_ids = "${var.alert_processor_vpc_security_group_ids}"
  }

  tags {
    Name = "StreamAlert"
  }
}

// Lambda Function: Alert Processor
//    Send alerts to declared outputs
//    Non VPC
resource "aws_lambda_function" "streamalert_alert_processor" {
  count         = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  function_name = "${var.prefix}_${var.cluster}_streamalert_alert_processor"
  description   = "StreamAlert Alert Processor"
  runtime       = "python2.7"
  role          = "${aws_iam_role.streamalert_alert_processor_role.arn}"
  handler       = "${lookup(var.alert_processor_config, "handler")}"
  memory_size   = "${var.alert_processor_memory}"
  timeout       = "${var.alert_processor_timeout}"
  s3_bucket     = "${lookup(var.alert_processor_config, "source_bucket")}"
  s3_key        = "${lookup(var.alert_processor_config, "source_object_key")}"

  environment {
    variables = {
      CLUSTER        = "${var.cluster}"
      LOGGER_LEVEL   = "${var.alert_processor_log_level}"
      ENABLE_METRICS = "${var.alert_processor_enable_metrics}"
    }
  }

  tags {
    Name = "StreamAlert"
  }
}

// Lambda Alias: Alert Processor Production
//    VPC
resource "aws_lambda_alias" "alert_processor_production_vpc" {
  count            = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  name             = "production"
  description      = "Production StreamAlert Alert Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_alert_processor_vpc.arn}"
  function_version = "${var.alert_processor_version}"
}

// Lambda Alias: Alert Processor Production
//    Non VPC
resource "aws_lambda_alias" "alert_processor_production" {
  count            = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  name             = "production"
  description      = "Production StreamAlert Alert Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_alert_processor.arn}"
  function_version = "${var.alert_processor_version}"
}

// Lambda Permission: Allow Lambda to invoke the Alert Processor
//    VPC
resource "aws_lambda_permission" "rule_processor_vpc" {
  count         = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  statement_id  = "AllowExecutionFromLambda"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_alert_processor_vpc.arn}"
  principal     = "lambda.amazonaws.com"
  source_arn    = "${aws_lambda_function.streamalert_rule_processor.arn}"
  qualifier     = "production"
  depends_on    = ["aws_lambda_alias.alert_processor_production_vpc"]
}

// Lambda Permission: Allow Lambda to invoke the Alert Processor
//    Non VPC
resource "aws_lambda_permission" "rule_processor" {
  count         = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  statement_id  = "AllowExecutionFromLambda"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_alert_processor.arn}"
  principal     = "lambda.amazonaws.com"
  source_arn    = "${aws_lambda_function.streamalert_rule_processor.arn}"
  qualifier     = "production"
  depends_on    = ["aws_lambda_alias.alert_processor_production"]
}

// Log Retention Policy: Rule Processor
resource "aws_cloudwatch_log_group" "rule_processor" {
  name              = "/aws/lambda/${var.prefix}_${var.cluster}_streamalert_rule_processor"
  retention_in_days = 60
}

// Log Retention Policy: Alert Processor
resource "aws_cloudwatch_log_group" "alert_processor" {
  name              = "/aws/lambda/${var.prefix}_${var.cluster}_streamalert_alert_processor"
  retention_in_days = 60
}

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
