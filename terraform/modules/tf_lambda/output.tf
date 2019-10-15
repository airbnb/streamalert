// Defined only if the Lambda is in a VPC
output "function_vpc_arn" {
  value = join(" ", aws_lambda_function.function_vpc.*.arn)
}

// Defined only if the Lambda is NOT in a VPC
output "function_no_vpc_arn" {
  value = join(" ", aws_lambda_function.function_no_vpc.*.arn)
}

output "role_arn" {
  value = aws_iam_role.role[0].arn
}

output "role_id" {
  value = aws_iam_role.role[0].id
}

// Combine the two mutually exclusive lists and export the first element as the function alias
output "function_alias" {
  value = element(
    concat(
      aws_lambda_alias.alias_vpc.*.name,
      aws_lambda_alias.alias_no_vpc.*.name,
    ),
    0,
  )
}

// Combine the two mutually exclusive lists and export the first element as the function name
output "function_name" {
  value = element(
    concat(
      aws_lambda_function.function_vpc.*.function_name,
      aws_lambda_function.function_no_vpc.*.function_name,
    ),
    0,
  )
}

// Combine the two mutually exclusive lists and export the first element as the function alias arn
output "function_alias_arn" {
  value = element(
    concat(
      aws_lambda_alias.alias_vpc.*.arn,
      aws_lambda_alias.alias_no_vpc.*.arn,
    ),
    0,
  )
}

// Log group name for this Lambda function to enable applying metrics filters
output "log_group_name" {
  value = element(
    concat(aws_cloudwatch_log_group.lambda_log_group.*.name, [""]),
    0,
  )
}
