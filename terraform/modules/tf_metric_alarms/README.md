# Custom Metric Alarms Terraform Module
This Terraform module creates metric alarms for custom metrics.

Creates `aws_cloudwatch_metric_alarm` resources for custom metrics. This is in its own module
due to Terraform interpolation restrictions.
