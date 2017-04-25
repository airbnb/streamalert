// SNS Topic to emit alerts to
resource "aws_sns_topic" "streamalert" {
  name         = "${var.prefix}_${var.cluster}_streamalerts"
  display_name = "${var.prefix}_${var.cluster}_streamalerts"
}

// Subscribe the Alert Processor Lambda function to the SNS topic
resource "aws_sns_topic_subscription" "alert_processor" {
  topic_arn = "${aws_sns_topic.streamalert.arn}"
  endpoint  = "${aws_lambda_function.streamalert_alert_processor.arn}:production"
  protocol  = "lambda"
}

// Subscribe the Rule Processor Lambda function to arbitrary SNS topics
resource "aws_sns_topic_subscription" "input_topic_subscriptions" {
  count     = "${length(keys(var.input_sns_topics))}"
  topic_arn = "${lookup(var.input_sns_topics, element(keys(var.input_sns_topics), count.index))}"
  endpoint  = "${aws_lambda_function.streamalert_rule_processor.arn}:production"
  protocol  = "lambda"
}
