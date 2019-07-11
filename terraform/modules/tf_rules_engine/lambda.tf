// Invoke rules engine Lambda from downloader SQS queue

# FIXME (derek.wang) Temporarily trigger from both old + new SQS; delete after migration
resource "aws_lambda_event_source_mapping" "invoke_via_sqs" {
  batch_size       = "${var.sqs_record_batch_size}"
  event_source_arn = "${var.legacy_classifier_sqs_queue_arn}"
  function_name    = "${var.function_alias_arn}"
}

resource "aws_lambda_event_source_mapping" "invoke_rules_via_sqs" {
  batch_size       = "${var.sqs_record_batch_size}"
  event_source_arn = "${var.new_classifier_sqs_queue_arn}"
  function_name    = "${var.function_alias_arn}"
}
