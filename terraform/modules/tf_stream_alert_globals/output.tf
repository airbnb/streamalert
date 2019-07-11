output "rules_table_arn" {
  value = "${element(concat(aws_dynamodb_table.rules_table.*.arn, list("")), 0)}"
}

# FIXME (derek.wang) Remove these post-migration
output "legacy_classifier_sqs_queue_url" {
  value = "${module.classifier_queue.legacy_sqs_queue_url}"
}
output "legacy_classifier_sqs_queue_arn" {
  value = "${module.classifier_queue.legacy_sqs_queue_arn}"
}

output "new_classifier_sqs_queue_url" {
  value = "${module.classifier_queue.new_sqs_queue_url}"
}

output "new_classifier_sqs_queue_arn" {
  value = "${module.classifier_queue.new_sqs_queue_arn}"
}

output "classifier_sqs_sse_kms_key_arn" {
  value = "${module.classifier_queue.sqs_sse_kms_key_arn}"
}
