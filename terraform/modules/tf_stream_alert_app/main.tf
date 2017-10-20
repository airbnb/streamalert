// Lambda Function: StreamAlert App
// Naming convention: '<prefix>_<cluster>_<service>_<app_name>_app'
resource "aws_lambda_function" "stream_alert_app" {
  function_name = "${var.function_prefix}_app"
  description   = "StreamAlert App for ${var.type}"
  runtime       = "python2.7"
  role          = "${aws_iam_role.stream_alert_app_role.arn}"
  handler       = "${lookup(var.stream_alert_apps_config, "handler")}"
  memory_size   = "${var.app_memory}"
  timeout       = "${var.app_timeout}"
  s3_bucket     = "${lookup(var.stream_alert_apps_config, "source_bucket")}"
  s3_key        = "${lookup(var.stream_alert_apps_config, "source_object_key")}"

  environment {
    variables = {
      CLUSTER      = "${var.cluster}"
      LOGGER_LEVEL = "${var.log_level}"
    }
  }

  dead_letter_config {
    target_arn = "arn:aws:sns:${var.region}:${var.account_id}:${var.monitoring_sns_topic}"
  }

  tags {
    Name = "StreamAlert"
    App  = "${var.type}"
  }
}

// Lambda Alias: StreamAlert App Production
resource "aws_lambda_alias" "app_production" {
  name             = "production"
  description      = "Production ${var.type} App Function Alias"
  function_name    = "${aws_lambda_function.stream_alert_app.arn}"
  function_version = "${var.current_version}"
}

// SSM Parameter Store value for the base config. Allow this to overwrite existing values
resource "aws_ssm_parameter" "config" {
  name      = "${var.function_prefix}_app_config"
  type      = "SecureString"
  value     = "${var.app_config_parameter}"
  overwrite = true
}

// AWS CloudWatch Event Rule for invoking StreamAlert App lambda on interval
resource "aws_cloudwatch_event_rule" "interval_rule" {
  name        = "${var.cluster}_${var.type}_app_interval_rule"
  description = "Schedule for executing the ${var.function_prefix}_app function"

  # https://amzn.to/2u5t0hS
  schedule_expression = "${var.interval}"
}

// AWS CloudWatch Event Target for the Event Rule
resource "aws_cloudwatch_event_target" "stream_alert_app_lambda_target" {
  rule = "${aws_cloudwatch_event_rule.interval_rule.name}"
  arn  = "${aws_lambda_function.stream_alert_app.arn}:production"

  depends_on = ["aws_lambda_alias.app_production"]
}

// Log Retention Policy: StreamAlert App function
resource "aws_cloudwatch_log_group" "stream_alert_app" {
  name              = "/aws/lambda/${var.function_prefix}_app"
  retention_in_days = 60
}
