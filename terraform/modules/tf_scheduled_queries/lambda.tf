#
# Osquery Events Query Lambda Function
#
# This lambda function is to issue a query against StreamAlert Athena table
# and send the Query Execution ID to a SQS queue for future process
#

module "scheduled_queries_lambda" {
  #
  # https://git.musta.ch/csirt/terraform-modules/tree/master/tf_lambda
  #
  # Using this reusable module will automatically generate some reusable stuff, including an
  # IAM Role, and it also auto-magically zips, hashes, and deploys the source code located
  # in a deployment path.
  source = "../tf_lambda"

  enabled       = true

  function_name = "${var.prefix}_streamalert_scheduled_queries_runner"
  description   = "Lambda function that powers StreamQuery, StreamAlert's scheduled query service"
  runtime       = "python3.7"
  handler       = "streamalert.scheduled_queries.main.handler"

  memory_size_mb        = var.lambda_memory
  timeout_sec           = var.lambda_timeout
  filename              = "scheduled_queries.zip"

  tags = {
    Component = "StreamQuery"
  }
  auto_publish_versions = true

  # Lambda Alarm configurations
  # FIXME (derek.wang)
//  log_retention_days         = var.lambda_log_retention
//  alarm_actions              = ["arn:aws:sns:${var.region}:${var.account_id}:airbnb_csirt_cloudwatch_alerts"]
//  errors_alarm_threshold     = var.lambda_error_threshold
//  errors_alarm_period_secs   = var.lambda_error_period
//  errors_alarm_enabled       = var.lambda_alarms_enabled
//  iterator_age_alarm_enabled = false
//  throttles_alarm_enabled    = false

  # Deployment configurations
  # FIXME
//  source_s3_bucket_name        = var.lambda_source_s3_bucket_name
//  source_s3_bucket_kms_key_arn = var.lambda_source_s3_bucket_kms_key_arn
//  deployment_package_path      = data.external.build_python_source_code.result.build_directory

  environment_variables = {
    REGION                = var.region
    ATHENA_DATABASE       = var.athena_database
    ATHENA_RESULTS_BUCKET = var.athena_results_bucket
    KINESIS_STREAM        = var.destination_kinesis_stream
  }
}

# CloudWatch schedules
resource "aws_cloudwatch_event_rule" "every_hour" {
  name                = "${var.prefix}_streamalert_scheduled_queries_schedule_hourly"
  description         = "Fires every hour"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_rule" "every_two_hours" {
  name                = "${var.prefix}_streamalert_scheduled_queries_schedule_two_hours"
  description         = "Fires every two hours"
  schedule_expression = "rate(2 hours)"
}

resource "aws_cloudwatch_event_rule" "every_day" {
  name                = "${var.prefix}_streamalert_scheduled_queries_schedule_daily"
  description         = "Fires every 24 hours"
  schedule_expression = "rate(24 hours)"
}

# CloudWatch schedule targets

# A sample cloudwatch event that is sent:
#   {
#     "version": "0",
#     "id": "91190ee0-a078-9c42-15b6-f3d418fae67d",
#     "detail-type": "Scheduled Event",
#     "source": "aws.events",
#     "account": "009715504418",
#     "time": "2019-06-14T18:39:21Z",
#     "region": "us-east-1",
#     "resources": [
#       "arn:aws:events:us-east-1:009715504418:rule/ryxias20190615_streamquery_schedule_hourly"
#     ],
#     "detail": {}
#   }
#
# This gets transformed into:
#   {
#     "name": "streamalert_streamquery_cloudwatch_trigger",
#     "event_id": "91190ee0-a078-9c42-15b6-f3d418fae67d",
#     "source_arn": "arn:aws:events:us-east-1:009715504418:rule/ryxias20190615_streamquery_schedule_hourly",
#     "function_start_time": "2019-06-14T18:39:21Z",
#     "tags": ["hourly", "production"]
#   }

resource "aws_cloudwatch_event_target" "run_step_function_every_hour" {
  rule     = aws_cloudwatch_event_rule.every_hour.name
  arn      = aws_sfn_state_machine.state_machine.id
  role_arn = aws_iam_role.iam_for_cloudwatch_schedule.arn

  input_transformer {
    input_paths = {
      time       = "$.time"
      id         = "$.id"
      source_arn = "$.resources[0]"
    }
    input_template = <<JSON
{
  "name": "streamalert_scheduled_queries_cloudwatch_trigger",
  "event_id": <id>,
  "source_arn": <source_arn>,
  "streamquery_configuration": {
    "clock": <time>,
    "tags": ["hourly", "${var.streamquery_environment}"]
  }
}
JSON

  }
}

resource "aws_cloudwatch_event_target" "run_step_function_every_two_hours" {
  rule     = aws_cloudwatch_event_rule.every_two_hours.name
  arn      = aws_sfn_state_machine.state_machine.id
  role_arn = aws_iam_role.iam_for_cloudwatch_schedule.arn

  input_transformer {
    input_paths = {
      time       = "$.time"
      id         = "$.id"
      source_arn = "$.resources[0]"
    }
    input_template = <<JSON
{
  "name": "streamalert_scheduled_queries_cloudwatch_trigger",
  "event_id": <id>,
  "source_arn": <source_arn>,
  "streamquery_configuration": {
    "clock": <time>,
    "tags": ["two_hours", "${var.streamquery_environment}"]
  }
}
JSON

  }
}

resource "aws_cloudwatch_event_target" "run_step_function_every_day" {
  rule     = aws_cloudwatch_event_rule.every_day.name
  arn      = aws_sfn_state_machine.state_machine.id
  role_arn = aws_iam_role.iam_for_cloudwatch_schedule.arn

  input_transformer {
    input_paths = {
      time       = "$.time"
      id         = "$.id"
      source_arn = "$.resources[0]"
    }
    input_template = <<JSON
{
  "name": "streamalert_scheduled_queries_cloudwatch_trigger",
  "event_id": <id>,
  "source_arn": <source_arn>,
  "streamquery_configuration": {
    "clock": <time>,
    "tags": ["daily", "${var.streamquery_environment}"]
  }
}
JSON

  }
}

#
# Execute a build script, which arranges all of the necessary project files into the build/
# directory prior to the tf_lambda module zipping them up.
#
# FIXME (derek.wang)
//data "external" "build_python_source_code" {
//  program = ["bash", "../../scripts/build.sh"]
//}

