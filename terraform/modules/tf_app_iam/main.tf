// IAM Role Policy: Allow the StreamAlert App function to invoke the Classifier function
resource "aws_iam_role_policy" "invoke_destination_function" {
  name   = "InvokeDestinationFunction"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.invoke_destination_function.json
}

// IAM Policy Doc: Allow the StreamAlert App function to invoke the Classifier function
data "aws_iam_policy_document" "invoke_destination_function" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.destination_function_name}",
    ]
  }
}

// IAM Role Policy: Allow the StreamAlert App function to create/update SSM Parameter Store Values
resource "aws_iam_role_policy" "parameter_store" {
  name   = "GetAndPutSSMParams"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.parameter_store.json
}

// IAM Policy Doc: Allow the StreamAlert App function to create/update SSM Parameter Store Values
data "aws_iam_policy_document" "parameter_store" {
  // Function needs to be able to get the auth and state parameters from Parameter Store
  statement {
    effect = "Allow"

    actions = [
      "ssm:GetParameters",
    ]

    resources = [
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_name}_auth",
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_name}_state",
    ]
  }

  // Function only needs to be able to put the state parameter back in Parameter Store
  statement {
    effect = "Allow"

    actions = [
      "ssm:PutParameter",
    ]

    resources = [
      "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.function_name}_state",
    ]
  }
}

// IAM Role Policy: Allow the StreamAlert App function to invoke itself
resource "aws_iam_role_policy" "invoke_self" {
  name   = "LambdaInvokeSelf"
  role   = var.function_role_id
  policy = data.aws_iam_policy_document.invoke_self.json
}

// IAM Policy Doc: Allow the StreamAlert App function to invoke itself
data "aws_iam_policy_document" "invoke_self" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.function_name}",
    ]
  }
}
