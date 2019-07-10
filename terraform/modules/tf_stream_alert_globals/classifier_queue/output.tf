# Using a list concat since terraform destroy throws errors if this does not exist

# FIXME (derek.wang) These two outputs are deprecated as the "classifier_queue" is deprecated
output "sqs_queue_url" {
  value = "${element(concat(aws_sqs_queue.classifier_queue.*.id, list("")), 0)}"
}
# Using a list concat since terraform destroy throws errors if this does not exist
output "sqs_queue_arn" {
  value = "${element(concat(aws_sqs_queue.classifier_queue.*.arn, list("")), 0)}"
}

output "destination_sqs_queue_url" {
  value = "${element(concat(aws_sqs_queue.classifier_destination_queue.*.id, list("")), 0)}"
}

# Using a list concat since terraform destroy throws errors if this does not exist
output "destination_sqs_queue_arn" {
  value = "${element(concat(aws_sqs_queue.classifier_destination_queue.*.arn, list("")), 0)}"
}

# Using a list concat since terraform destroy throws errors if this does not exist
output "sqs_sse_kms_key_arn" {
  value = "${element(concat(aws_kms_key.sqs_sse.*.arn, list("")), 0)}"
}
