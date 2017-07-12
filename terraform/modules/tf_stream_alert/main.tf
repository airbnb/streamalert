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

// Lambda Permission: Allow SNS to invoke the Alert Processor
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

// Lambda Permission: Allow SNS to invoke the Alert Processor
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
