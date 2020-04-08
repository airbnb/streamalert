// Invoke rules engine Lambda from downloader SQS queue
resource "aws_lambda_event_source_mapping" "invoke_via_sqs" {
  batch_size       = var.sqs_record_batch_size
  event_source_arn = var.classifier_sqs_queue_arn
  function_name    = var.function_alias_arn
}
