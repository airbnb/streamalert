output "cloudwatch_logs_subscription_role_arn" {
  value = aws_iam_role.subscription_role.arn
}
