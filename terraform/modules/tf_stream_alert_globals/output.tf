output "rules_table_arn" {
  value = "${element(concat(aws_dynamodb_table.rules_table.*.arn, list("")), 0)}"
}

# FIXME (derek.wang) Remove these post-migration
output "classifier_sqs_queue_url" {
  value = "${module.classifier_queue.sqs_queue_url}"
}
output "classifier_sqs_queue_arn" {
  value = "${module.classifier_queue.sqs_queue_arn}"
}

output "classifier_sqs_sse_kms_key_arn" {
  value = "${module.classifier_queue.sqs_sse_kms_key_arn}"
}

output "classifier_destination_sqs_queue_url" {
  value = "${module.classifier_queue.destination_sqs_queue_url}"
}

output "classifier_destination_sqs_queue_arn" {
  value = "${module.classifier_queue.destination_sqs_queue_arn}"
}
