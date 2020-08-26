output "cloudtrail_to_cloudwatch_logs_role" {
  value = aws_iam_role.cloudtrail_to_cloudwatch_role.arn
}

// CloudTrail requires the log stream wildcard here
output "cloudwatch_logs_group_arn" {
  value = "${aws_cloudwatch_log_group.cloudtrail_logging.arn}:*"
}
