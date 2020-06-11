# Role id of the lambda function that runs scheduled queries
output "lambda_function_role_id" {
  value = module.scheduled_queries_lambda.role_id
}