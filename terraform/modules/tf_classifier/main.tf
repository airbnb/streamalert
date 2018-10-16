// SQS Queue: Send logs from the Classifier to the SQS queue
resource "aws_sqs_queue" "classifier_queue" {
  name = "streamalert_classified_logs"

  # Enables SQS Long Polling: https://amzn.to/2wn10CR
  receive_wait_time_seconds = 10

  # The amount of time messages are hidden after being received from a consumer
  # Default this to 2 seconds longer than the maximum AWS Lambda duration
  visibility_timeout_seconds = "302"

  # Enable server-side encryption of messages in the queue
  kms_master_key_id = "${aws_kms_key.sse.arn}"

  tags {
    Name = "StreamAlert"
  }
}

// SQS Queue Policy: Allow the Classifier to send messages to SQS
resource "aws_sqs_queue_policy" "classifier_queue" {
  queue_url = "${aws_sqs_queue.classifier_queue.id}"
  policy    = "${data.aws_iam_policy_document.classifier_queue.json}"
}

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
  depends_on    = ["${var.function_alias_arn}"]
}
