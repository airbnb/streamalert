output "lambda_arn" {
  value = "${aws_lambda_function.streamalert_rule_processor.arn}"
}

output "lambda_role_arn" {
  value = "${aws_iam_role.streamalert_rule_processor_role.arn}"
}

output "lambda_role_id" {
  value = "${aws_iam_role.streamalert_rule_processor_role.id}"
}

output "sns_topic_arn" {
  value = "${aws_sns_topic.streamalert.arn}"
}
