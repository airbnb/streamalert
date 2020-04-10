// Generic module for any StreamAlert Lambda function

locals {
  schedule_enabled = var.schedule_expression != ""
  vpc_enabled      = length(var.vpc_subnet_ids) > 0
  tags             = merge(var.default_tags, var.tags)
}

// Lambda function, with optional VPC config
resource "aws_lambda_function" "function" {
  function_name = var.function_name
  description   = var.description
  runtime       = var.runtime
  role          = aws_iam_role.role.arn
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

  # Empty values for both of these values will prevent a vpc_config from being used
  # https://www.terraform.io/docs/providers/aws/r/lambda_function.html#subnet_ids
  vpc_config {
    subnet_ids         = var.vpc_subnet_ids
    security_group_ids = var.vpc_security_group_ids
  }

  layers = var.layers

  tags = local.tags
}

resource "aws_lambda_alias" "alias" {
  name             = var.alias_name
  description      = "${var.alias_name} alias for ${aws_lambda_function.function.function_name}"
  function_name    = aws_lambda_function.function.function_name
  function_version = aws_lambda_function.function.version
}

// Allow Lambda function to be invoked via a CloudWatch event rule (if applicable)
resource "aws_lambda_permission" "allow_cloudwatch_invocation" {
  count         = local.schedule_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch_${aws_lambda_function.function.function_name}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.invocation_schedule[0].arn
  qualifier     = aws_lambda_alias.alias.name
}

// Lambda Permission: Allow SNS to invoke this function
resource "aws_lambda_permission" "sns_inputs" {
  count         = length(var.input_sns_topics)
  statement_id  = "AllowExecutionFromSNS${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.function.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = element(var.input_sns_topics, count.index)
  qualifier     = aws_lambda_alias.alias.name
}
