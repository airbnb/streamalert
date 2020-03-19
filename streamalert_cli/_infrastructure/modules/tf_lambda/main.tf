// Generic module for any StreamAlert Lambda function.
// TODO - migrate all Lambda functions and Lambda metric alarms to use this module

locals {
  schedule_enabled = var.schedule_expression != ""
  vpc_enabled      = length(var.vpc_subnet_ids) > 0
  tags             = merge(var.default_tags, var.tags)
}

// Either the function_vpc or the function_no_vpc resource will be used
resource "aws_lambda_function" "function_vpc" {
  count         = var.enabled && local.vpc_enabled ? 1 : 0
  function_name = var.function_name
  description   = var.description
  runtime       = var.runtime
  role          = aws_iam_role.role[0].arn
  handler       = var.handler
  memory_size   = var.memory_size_mb
  publish       = var.auto_publish_versions
  timeout       = var.timeout_sec

  filename         = var.filename
  source_code_hash = filebase64sha256(var.filename)

  // Maximum number of concurrent executions allowed
  reserved_concurrent_executions = var.concurrency_limit

  environment {
    variables = var.environment_variables
  }

  // Empty vpc_config lists are theoretically supported, but it actually breaks subsequent deploys:
  // https://github.com/terraform-providers/terraform-provider-aws/issues/443
  vpc_config {
    security_group_ids = var.vpc_security_group_ids
    subnet_ids         = var.vpc_subnet_ids
  }

  tags = local.tags

  // We need VPC access before the function can be created
  depends_on = [aws_iam_role_policy_attachment.vpc_access]
}

resource "aws_lambda_alias" "alias_vpc" {
  count            = var.enabled && local.vpc_enabled ? 1 : 0
  name             = var.alias_name
  description      = "${var.alias_name} alias for ${var.function_name}"
  function_name    = var.function_name
  function_version = var.aliased_version == "" ? aws_lambda_function.function_vpc[0].version : var.aliased_version
  depends_on       = [aws_lambda_function.function_vpc]
}

resource "aws_lambda_function" "function_no_vpc" {
  count         = var.enabled && false == local.vpc_enabled ? 1 : 0
  function_name = var.function_name
  description   = var.description
  runtime       = var.runtime
  role          = aws_iam_role.role[0].arn
  handler       = var.handler
  memory_size   = var.memory_size_mb
  publish       = var.auto_publish_versions
  timeout       = var.timeout_sec

  filename         = var.filename
  source_code_hash = filebase64sha256(var.filename)

  // Maximum number of concurrent executions allowed
  reserved_concurrent_executions = var.concurrency_limit

  environment {
    variables = var.environment_variables
  }

  tags = local.tags
}

resource "aws_lambda_alias" "alias_no_vpc" {
  count            = var.enabled && false == local.vpc_enabled ? 1 : 0
  name             = var.alias_name
  description      = "${var.alias_name} alias for ${var.function_name}"
  function_name    = var.function_name
  function_version = var.aliased_version == "" ? aws_lambda_function.function_no_vpc[0].version : var.aliased_version
  depends_on       = [aws_lambda_function.function_no_vpc]
}

// Allow Lambda function to be invoked via a CloudWatch event rule (if applicable)
resource "aws_lambda_permission" "allow_cloudwatch_invocation" {
  count         = var.enabled && local.schedule_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch_${var.function_name}"
  action        = "lambda:InvokeFunction"
  function_name = var.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.invocation_schedule[0].arn
  qualifier     = var.alias_name

  // The alias must be created before we can grant permission to invoke it
  depends_on = [
    aws_lambda_alias.alias_vpc,
    aws_lambda_alias.alias_no_vpc,
  ]
}

// Lambda Permission: Allow SNS to invoke this function
resource "aws_lambda_permission" "sns_inputs" {
  count         = length(var.input_sns_topics)
  statement_id  = "AllowExecutionFromSNS${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = var.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = element(var.input_sns_topics, count.index)
  qualifier     = "production"
  depends_on = [
    aws_lambda_alias.alias_vpc,
    aws_lambda_alias.alias_no_vpc,
  ]
}
