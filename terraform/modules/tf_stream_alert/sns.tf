// SNS Topic to emit alerts to
resource "aws_sns_topic" "streamalert" {
  name         = "${var.prefix}_${var.cluster}_streamalerts"
  display_name = "${var.prefix}_${var.cluster}_streamalerts"
}

// Subscribe the Alert Processor Lambda function to the SNS topic
resource "aws_sns_topic_subscription" "alert_processor" {
  topic_arn = "${aws_sns_topic.streamalert.arn}"
  endpoint  = "${aws_lambda_function.streamalert_alert_processor.arn}"
  protocol  = "lambda"
}
