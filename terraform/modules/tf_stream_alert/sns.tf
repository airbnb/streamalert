// SNS Topic to emit alerts to
resource "aws_sns_topic" "streamalert" {
  name         = "${var.prefix}_${var.cluster}_streamalerts"
  display_name = "${var.prefix}_${var.cluster}_streamalerts"
}

// Subscribe the Alert Processor Lambda function to the SNS topic
// VPC
resource "aws_sns_topic_subscription" "alert_processor_vpc" {
  count     = "${var.alert_processor_vpc_enabled ? 1 : 0}"
  topic_arn = "${aws_sns_topic.streamalert.arn}"
  endpoint  = "${aws_lambda_function.streamalert_alert_processor_vpc.arn}:production"
  protocol  = "lambda"
}

// Non VPC
resource "aws_sns_topic_subscription" "alert_processor" {
  count     = "${var.alert_processor_vpc_enabled ? 0 : 1}"
  topic_arn = "${aws_sns_topic.streamalert.arn}"
  endpoint  = "${aws_lambda_function.streamalert_alert_processor.arn}:production"
  protocol  = "lambda"
}

// Subscribe the Rule Processor Lambda function to arbitrary SNS topics
resource "aws_sns_topic_subscription" "input_topic_subscriptions" {
  count     = "${length(var.input_sns_topics)}"
  topic_arn = "${element(var.input_sns_topics, count.index)}"
  endpoint  = "${aws_lambda_function.streamalert_rule_processor.arn}:production"
  protocol  = "lambda"
}
