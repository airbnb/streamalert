output "lambda_arn" {
  value = aws_lambda_function.athena_partition_refresh.arn
}

output "lambda_role_arn" {
  value = aws_iam_role.athena_partition_role.arn
}

output "lambda_role_id" {
  value = aws_iam_role.athena_partition_role.id
}

output "results_bucket_arn" {
  value = aws_s3_bucket.athena_results_bucket.arn
}
