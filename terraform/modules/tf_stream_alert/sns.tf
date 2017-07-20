// SNS Topic Subscription: Subscribe the Rule Processor to configured SNS topics
resource "aws_sns_topic_subscription" "input_topic_subscriptions" {
  count     = "${length(var.input_sns_topics)}"
  topic_arn = "${element(var.input_sns_topics, count.index)}"
  endpoint  = "${aws_lambda_function.streamalert_rule_processor.arn}:production"
  protocol  = "lambda"
}

// Lambda Permission: Allow SNS to invoke the Rule Processor
resource "aws_lambda_permission" "sns_inputs" {
  count         = "${length(var.input_sns_topics)}"
  statement_id  = "AllowExecutionFromSNS${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.streamalert_rule_processor.arn}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${element(var.input_sns_topics, count.index)}"
  qualifier     = "production"
}
