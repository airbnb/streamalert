// SNS Topic Subscription: Subscribe the Classifier to configured SNS topics
resource "aws_sns_topic_subscription" "input_topic_subscriptions" {
  count     = length(var.input_sns_topics)
  topic_arn = element(var.input_sns_topics, count.index)
  endpoint  = var.function_alias_arn
  protocol  = "lambda"
}
