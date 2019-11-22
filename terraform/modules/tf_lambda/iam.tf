data "aws_iam_policy_document" "lambda_execution_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// Create the execution role for the Lambda function.
resource "aws_iam_role" "role" {
  count              = var.enabled ? 1 : 0
  name               = "${var.function_name}_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.lambda_execution_policy.json

  tags = local.tags
}

// Attach write permissions for CloudWatch logs
resource "aws_iam_role_policy_attachment" "logs_metrics_policy" {
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.role[0].id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

// Attach VPC policy (if applicable)
resource "aws_iam_role_policy_attachment" "vpc_access" {
  count      = var.enabled && local.vpc_enabled ? 1 : 0
  role       = aws_iam_role.role[0].id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
