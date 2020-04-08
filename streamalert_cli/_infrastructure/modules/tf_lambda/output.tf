output "function_arn" {
  value = aws_lambda_function.function.arn
}

output "role_arn" {
  value = aws_iam_role.role.arn
}

output "role_id" {
  value = aws_iam_role.role.id
}

output "function_alias" {
  value = aws_lambda_alias.alias.name
}

output "function_name" {
  value = aws_lambda_function.function.function_name
}

output "function_alias_arn" {
  value = aws_lambda_alias.alias.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.lambda_log_group.name
}
