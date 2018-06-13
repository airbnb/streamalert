# Lambda Module
This Terraform module creates a single AWS Lambda function and its related components:

* IAM execution role with basic permissions
* Lambda function
* Versions and an alias
* CloudWatch event schedule support (to invoke at regular intervals)
* CloudWatch log group
* CloudWatch metric alarms related to Lambda

All StreamAlert Lambda functions will eventually leverage this module.

The created IAM role has permission to publish CloudWatch logs and metrics. To add function-specific
permissions, attach/inline them to the created IAM role.

## Example
```hcl
module "alert_processor" {
  function_name     = "alert_processor"
  handler           = "stream_alert.alert_processor.main.handler"
  filename          = "alert_processor.zip"

  environment_variables = {
    LOGGER_LEVEL = "info"
  }
  
  // Commonly used optional variables
  enabled                   = true
  description               = "Function Description"
  memory_size_mb            = 128
  timeout_sec               = 60
  vpc_subnet_ids            = ["abc"]
  vpc_security_group_ids    = ["id0"]
  aliased_version           = 1
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
If your Lambda function is in a VPC, `function_vpc_arn` is the ARN of the generated Lambda
function. Otherwise, it will be `function_no_vpc_arn`. (This split is a workaround for a
[Terraform bug](https://github.com/terraform-providers/terraform-provider-aws/issues/443)).

This module also exports the `role_arn` and `role_id` for the Lambda execution role.