output "lambda_arn" {
  value = "${aws_lambda_function.stream_alert_processor.arn}"
}

output "lambda_role_arn" {
  value = "${aws_iam_role.stream_alert_lambda_role.arn}"
}

output "lambda_role_id" {
  value = "${aws_iam_role.stream_alert_lambda_role.id}"
}

output "sns_topic_arn" {
  value = "${aws_sns_topic.streamalert.arn}"
}
