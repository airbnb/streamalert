output "rules_table_arn" {
  value = "${element(concat(aws_dynamodb_table.rules_table.*.arn, list("")), 0)}"
}

output "classifier_sqs_queue_url" {
  value = "${module.classifier_queue.sqs_queue_url}"
}

output "classifier_sqs_queue_arn" {
  value = "${module.classifier_queue.sqs_queue_arn}"
}
