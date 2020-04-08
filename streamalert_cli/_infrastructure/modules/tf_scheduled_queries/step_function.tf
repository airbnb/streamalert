/*
 * Builds the StepFunction that powers most of StreamQuery
 * https://www.terraform.io/docs/providers/aws/r/sfn_state_machine.html
 */
resource "aws_sfn_state_machine" "state_machine" {
  name = "${var.prefix}_streamalert_scheduled_queries_state_machine"

  role_arn = aws_iam_role.iam_for_step_functions.arn

  # This state machine is largely inspired by the "job poller" pattern:
  # https://docs.aws.amazon.com/step-functions/latest/dg/sample-project-job-poller.html
  definition = <<EOF
{
  "Comment": "State Machine definition for StreamAlert scheduled queries",
  "StartAt": "RunFunction",
  "TimeoutSeconds": ${var.sfn_timeout_secs},
  "States": {
    "RunFunction": {
      "Comment":  "Call the scheduled queries lambda function to start queries and to report on their statuses",
      "Type": "Task",
      "Resource": "${module.scheduled_queries_lambda.function_alias_arn}",
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
      "Comment": "Not all queries are completed; this state waits for a specified duration before checking again",
      "Type": "Wait",
      "Seconds": ${var.sfn_wait_secs},
      "Next": "RunFunction"
    },
    "Done": {
      "Comment": "All queries have completed",
      "Type": "Pass",
      "Result": {
        "message": "StreamQuery Execution completed"
      },
      "ResultPath": "$.System",
      "End": true
    },
    "FatalError": {
      "Comment": "Something went wrong that caused the scheduled queries Lambda function to not return properly",
      "Type": "Fail",
      "Cause": "Something invalid happened",
      "Error": "StreamAlert scheduled query execution failed permanently"
    }
  }
}
EOF

  tags = {
    Name = "StreamAlert"
  }

}
