output "rules_table_arn" {
  value = element(concat(aws_dynamodb_table.rules_table.*.arn, [""]), 0)
}

output "classifier_sqs_queue_url" {
  value = module.classifier_queue.sqs_queue_url
}

output "classifier_sqs_queue_arn" {
  value = module.classifier_queue.sqs_queue_arn
}

output "classifier_sqs_sse_kms_key_arn" {
  value = module.classifier_queue.sqs_sse_kms_key_arn
}

output "lamdba_layer_arns" {
  value = [
    aws_lambda_layer_version.aliyun_dependencies.arn,
    aws_lambda_layer_version.box_dependencies.arn,
  ]
}
