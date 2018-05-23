output "cloudwatch_subscription_role_arn" {
  value = "${aws_iam_role.cloudwatch_subscription_role.arn}"
}
