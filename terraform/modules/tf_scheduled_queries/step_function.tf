# Builds the StepFunction that powers most of StreamQuery
#
# https://www.terraform.io/docs/providers/aws/r/sfn_state_machine.html
resource "aws_sfn_state_machine" "state_machine" {
  name = "${var.prefix}_streamquery_state_machine"

  role_arn = aws_iam_role.iam_for_step_functions.arn

  # This state machine is largely inspired by the "job poller" pattern:
  # https://docs.aws.amazon.com/step-functions/latest/dg/sample-project-job-poller.html
  definition = <<EOF
{
  "Comment": "Derek Wang testing a state machine for lambda",
  "StartAt": "RunFunction",
  "TimeoutSeconds": 3000,
  "States": {
    "RunFunction": {
      "Comment":  "This task calls the lamdba over and over until done",
      "Type": "Task",
      "Resource": "${module.streamquery_lambda.function_alias_arn}",
      "Next": "CheckIfDone",
      "TimeoutSeconds": 60
    },
    "CheckIfDone": {
      "Comment":  "Depending on the return value of the Lambda, move to done or retry",
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.done",
          "NumericEquals": 1,
          "Next": "Done"
        },
        {
          "Variable": "$.continue",
          "NumericEquals": 1,
          "Next": "Wait"
        }
      ],
      "Default": "FatalError"
    },
    "Wait": {
      "Comment": "This state simply waits for 20 seconds",
      "Type": "Wait",
      "Seconds": 20,
      "Next": "RunFunction"
    },
    "Done": {
      "Comment": "We gucci",
      "Type": "Pass",
      "Result": {
        "message": "StreamQuery Execution completed"
      },
      "ResultPath": "$.System",
      "End": true
    },
    "FatalError": {
      "Comment": "omg y u no work",
      "Type": "Fail",
      "Cause": "Something invalid happened",
      "Error": "Omg What invalid vegeta what 9000??"
    }
  }
}
EOF

}

