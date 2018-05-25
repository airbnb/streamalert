output "cloudwatch_subscription_role_arn" {
  value = "${aws_iam_role.cloudwatch_subscription_role.arn}"
}

output "cloudwatch_destination_arn" {
  value = "${aws_cloudwatch_log_destination.cloudwatch_kinesis.arn}"
}
