// AWS Lambda Function: StreamAlert Processor
//    Matches rules against logs from Kinesis Streams or S3
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

// StreamAlert Processor Production Alias
resource "aws_lambda_alias" "rule_processor_production" {
  name             = "production"
  description      = "Production StreamAlert Rule Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_rule_processor.arn}"
  function_version = "${var.rule_processor_version}"
}

// Allow SNS to invoke the StreamAlert Output Processor
resource "aws_lambda_permission" "sns_inputs" {
  count         = "${length(var.input_sns_topics)}"
  statement_id  = "AllowExecutionFromSNS${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_rule_processor.arn}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${element(var.input_sns_topics, count.index)}"
  qualifier     = "production"
}

// AWS Lambda Function: StreamAlert Alert Processor
//    Send alerts to declared outputs

// Lambda Function inside a VPC
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

// Non VPC Lambda Function
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

// StreamAlert Output Processor Production Alias
// VPC
resource "aws_lambda_alias" "alert_processor_production_vpc" {
  count            = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  name             = "production"
  description      = "Production StreamAlert Alert Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_alert_processor_vpc.arn}"
  function_version = "${var.alert_processor_version}"
}

// Non VPC
resource "aws_lambda_alias" "alert_processor_production" {
  count            = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  name             = "production"
  description      = "Production StreamAlert Alert Processor Alias"
  function_name    = "${aws_lambda_function.streamalert_alert_processor.arn}"
  function_version = "${var.alert_processor_version}"
}

// Allow SNS to invoke the Alert Processor
// VPC
resource "aws_lambda_permission" "with_sns_vpc" {
  count         = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_alert_processor_vpc.arn}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.streamalert.arn}"
  qualifier     = "production"
  depends_on    = ["aws_lambda_alias.alert_processor_production_vpc"]
}

// Non VPC
resource "aws_lambda_permission" "with_sns" {
  count         = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_alert_processor.arn}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.streamalert.arn}"
  qualifier     = "production"
  depends_on    = ["aws_lambda_alias.alert_processor_production"]
}

// S3 bucket for S3 outputs
resource "aws_s3_bucket" "streamalerts" {
  bucket        = "${replace("${var.prefix}.${var.cluster}.streamalerts", "_", ".")}"
  acl           = "private"
  force_destroy = false

  versioning {
    enabled = true
  }
}
