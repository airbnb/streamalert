# Metric Filters Terraform Module
This Terraform module creates metric filters that are applied to CloudWatch Log Group(s).

Creates `aws_cloudwatch_log_metric_filter` resources for custom metrics. This is in its own module
due to Terraform interpolation restrictions.
