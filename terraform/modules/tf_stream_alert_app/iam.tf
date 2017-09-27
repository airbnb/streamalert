// IAM Role: StreamAlert App Execution Role
resource "aws_iam_role" "stream_alert_app_role" {
  name               = "${var.function_prefix}_app_role"
  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role_policy.json}"
}

// IAM Policy Doc: Generic Lambda AssumeRole
data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// IAM Role Policy: Allow the StreamAlert App function to invoke the Rule Processor
resource "aws_iam_role_policy" "stream_alert_app_role_policy" {
  name   = "${var.function_prefix}_app_role_policy"
  role   = "${aws_iam_role.stream_alert_app_role.id}"
  policy = "${data.aws_iam_policy_document.app_invoke_rule_proc.json}"
}

// IAM Policy Doc: Allow the StreamAlert App function to invoke the Rule Processor
data "aws_iam_policy_document" "app_invoke_rule_proc" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}_${var.cluster}_streamalert_rule_processor",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      "arn:aws:sns:${var.region}:${var.account_id}:${var.monitoring_sns_topic}",
    ]
  }

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

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
    ]

    resources = [
      "${aws_cloudwatch_log_group.stream_alert_app.arn}",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:${aws_cloudwatch_log_group.stream_alert_app.name}:log-stream:*",
    ]
  }
}

// Lambda Permission: Allow Cloudwatch Scheduled Events to invoke StreamAlert App Lambda
resource "aws_lambda_permission" "allow_cloudwatch_events_invocation" {
  statement_id  = "CloudwatchEventsInvokeAthenaRefresh"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.stream_alert_app.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.interval_rule.arn}"
  qualifier     = "production"

  depends_on = ["aws_lambda_alias.app_production"]
}
