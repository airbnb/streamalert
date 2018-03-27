// IAM Role Policy: Allow the StreamAlert App function to invoke the Rule Processor
resource "aws_iam_role_policy" "stream_alert_app_invoke_rule_lambda_role_policy" {
  name   = "${var.cluster}_${var.type}_app_invoke_rule_lambda_role_policy"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.app_invoke_rule_processor_policy.json}"
}

// IAM Policy Doc: Allow the StreamAlert App function to invoke the Rule Processor
data "aws_iam_policy_document" "app_invoke_rule_processor_policy" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_${var.cluster}_streamalert_rule_processor",
    ]
  }
}

// IAM Role Policy: Allow the StreamAlert App function to create/update SSM Parameter Store Values
resource "aws_iam_role_policy" "stream_alert_app_parameter_store_role_policy" {
  name   = "${var.cluster}_${var.type}_app_parameter_store_role_policy"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.app_parameter_store_policy.json}"
}

// IAM Policy Doc: Allow the StreamAlert App function to create/update SSM Parameter Store Values
data "aws_iam_policy_document" "app_parameter_store_policy" {
  // Function needs to be able to get the auth, base config, and state parameters from Parameter Store
  statement {
    effect = "Allow"

    actions = [
      "ssm:GetParameters",
    ]

    resources = [
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_prefix}_app_auth",
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_prefix}_app_config",
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_prefix}_app_state",
    ]
  }

  // Function only needs to be able to put the state parameter back in Parameter Store
  statement {
    effect = "Allow"

    actions = [
      "ssm:PutParameter",
    ]

    resources = [
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_prefix}_app_state",
    ]
  }
}

// IAM Role Policy: Allow the StreamAlert App function to invoke itself
resource "aws_iam_role_policy" "stream_alert_app_invoke_self_lambda_role_policy" {
  name   = "${var.cluster}_${var.type}_app_invoke_self_lambda_role_policy"
  role   = "${var.role_id}"
  policy = "${data.aws_iam_policy_document.app_invoke_self_policy.json}"
}

// IAM Policy Doc: Allow the StreamAlert App function to invoke itself
data "aws_iam_policy_document" "app_invoke_self_policy" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.function_prefix}_app",
    ]
  }
}
