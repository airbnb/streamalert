// Generic module for any StreamAlert Lambda function.
// TODO - migrate all Lambda functions and Lambda metric alarms to use this module

resource "aws_lambda_function" "function" {
  count         = "${var.enabled}"
  function_name = "${var.function_name}"
  description   = "${var.description}"
  runtime       = "${var.runtime}"
  role          = "${aws_iam_role.role.arn}"
  handler       = "${var.handler}"
  memory_size   = "${var.memory_size_mb}"
  timeout       = "${var.timeout_sec}"
  s3_bucket     = "${var.source_bucket}"
  s3_key        = "${var.source_object_key}"

  environment {
    variables = "${var.environment_variables}"
  }

  // Note: If both of these lists are empty, VPC will not be enabled
  vpc_config {
    security_group_ids = "${var.vpc_subnet_ids}"
    subnet_ids         = "${var.vpc_security_group_ids}"
  }

  tags {
    Name = "${var.name_tag}"
  }
}

resource "aws_lambda_alias" "production_alias" {
  count            = "${var.enabled}"
  name             = "production"
  description      = "Production alias for ${aws_lambda_function.function.function_name}"
  function_name    = "${aws_lambda_function.function.function_name}"
  function_version = "${var.aliased_version == "" ? aws_lambda_function.function.version : var.aliased_version}"
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count             = "${var.enabled}"
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = "${var.log_retention_days}"

  tags {
    Name = "${var.name_tag}"
  }
}
