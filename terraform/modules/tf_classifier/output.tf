output "sqs_queue_url" {
  value = "${aws_sqs_queue.classifier_queue.id}"
}

output "lambda_role_arn" {
  value = "${aws_iam_role.streamalert_rule_processor_role.arn}"
}

output "lambda_role_id" {
  value = "${aws_iam_role.streamalert_rule_processor_role.id}"
}
