# Using a list concat since terraform destroy throws errors if this does not exist
output "sqs_queue_url" {
  value = element(concat(aws_sqs_queue.classifier_queue.*.id, [""]), 0)
}

# Using a list concat since terraform destroy throws errors if this does not exist
output "sqs_queue_arn" {
  value = element(concat(aws_sqs_queue.classifier_queue.*.arn, [""]), 0)
}

# Using a list concat since terraform destroy throws errors if this does not exist
output "sqs_sse_kms_key_arn" {
  value = element(concat(aws_kms_key.sqs_sse.*.arn, [""]), 0)
}

