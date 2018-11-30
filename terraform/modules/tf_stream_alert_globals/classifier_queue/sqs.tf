// SQS Queue: Send logs from the Classifier to the SQS queue
resource "aws_sqs_queue" "classifier_queue" {
  name = "streamalert_classified_logs"

  # Enables SQS Long Polling: https://amzn.to/2wn10CR
  receive_wait_time_seconds = 10

  # The amount of time messages are hidden after being received from a consumer
  # Default this to 2 seconds longer than the maximum AWS Lambda duration
  visibility_timeout_seconds = "${var.rules_engine_timeout}"

  # Enable queue encryption of messages in the queue
  kms_master_key_id = "${aws_kms_key.sqs_sse.arn}"

  tags {
    Name = "StreamAlert"
  }
}
