module "scheduled_queries_lambda" {
  source = "../tf_lambda"

  function_name = "${var.prefix}_streamalert_scheduled_queries_runner"
  description   = "Lambda function that powers StreamQuery, StreamAlert's scheduled query service"
  runtime       = var.runtime
  handler       = var.lambda_handler

  memory_size_mb = var.lambda_memory
  timeout_sec    = var.lambda_timeout

  concurrency_limit = var.lambda_concurrency_limit

  environment_variables = {
    REGION                = var.region
    ATHENA_DATABASE       = var.athena_database
    ATHENA_RESULTS_BUCKET = var.athena_results_bucket
    KINESIS_STREAM        = var.destination_kinesis_stream
    LOGGER_LEVEL          = var.lambda_log_level
  }

  tags = {
    Subcomponent = "StreamQuery"
  }

  auto_publish_versions = true

  log_retention_days = var.lambda_log_retention_days
  alarm_actions      = var.lambda_alarm_actions

  errors_alarm_enabled            = var.lambda_alarms_enabled
  errors_alarm_evaluation_periods = var.lambda_error_evaluation_periods
  errors_alarm_period_secs        = var.lambda_error_period_secs
  errors_alarm_threshold          = var.lambda_error_threshold
}
