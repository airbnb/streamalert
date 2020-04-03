# Lambda Module
This Terraform module creates a single AWS Lambda function and its related components:

* IAM execution role with basic permissions
* Lambda function
* Versions and an alias
* CloudWatch event schedule support (to invoke at regular intervals)
* CloudWatch log group
* CloudWatch metric alarms related to Lambda

All StreamAlert Lambda functions should leverage this module.

The created IAM role has permission to publish CloudWatch logs and metrics. To add function-specific
permissions, attach them to the created IAM role.

## Example
```hcl
module "alert_processor" {
  function_name     = "alert_processor"
  handler           = "streamalert.alert_processor.main.handler"
  filename          = "alert_processor.zip"

  environment_variables = {
    LOGGER_LEVEL = "info"
  }

  // Commonly used optional variables
  description               = "Function Description"
  memory_size_mb            = 128
  timeout_sec               = 60
  vpc_subnet_ids            = ["abc"]
  vpc_security_group_ids    = ["id0"]
  log_retention_days        = 14
  alarm_actions             = ["SNS_ARN"]
  errors_alarm_threshold    = 1
  enable_iterator_age_alarm = true
}

// Add additional permissions
resource "aws_iam_role_policy" "policy" {
  name   = "CustomPolicy"
  role   = "${module.alert_processor.role_id}"
  policy = "${data.aws_iam_policy_document.policy.json}"
}

data "aws_iam_policy_document" "policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::..."]
  }
}
```

For a complete list of available options and their descriptions, see [`variables.tf`](variables.tf).

## Outputs
This module exports the `function_arn` for the Lambda function, along with the `role_arn`, and `role_id` for the Lambda execution role.
