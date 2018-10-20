// SNS Topic Subscription: Subscribe the Classifier to configured SNS topics
resource "aws_sns_topic_subscription" "input_topic_subscriptions" {
  count     = "${length(var.input_sns_topics)}"
  topic_arn = "${element(var.input_sns_topics, count.index)}"
  endpoint  = "${var.function_alias_arn}"
  protocol  = "lambda"
}

// Lambda Permission: Allow SNS to invoke the Classifier
resource "aws_lambda_permission" "sns_inputs" {
  count         = "${length(var.input_sns_topics)}"
  statement_id  = "AllowExecutionFromSNS${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = "${var.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${element(var.input_sns_topics, count.index)}"
  qualifier     = "production"
  depends_on    = ["aws_lambda_alias.rule_processor_production"]
}
