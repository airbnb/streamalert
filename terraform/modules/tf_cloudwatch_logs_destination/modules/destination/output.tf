output "cloudwatch_logs_destination_arn" {
  value = aws_cloudwatch_log_destination.cloudwatch_to_kinesis.arn
}
