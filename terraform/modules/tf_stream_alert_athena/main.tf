// Lambda Function: Athena Parition Refresh
resource "aws_lambda_function" "athena_partition_refresh" {
  function_name = "${var.prefix}_streamalert_athena_partition_refresh"
  description   = "StreamAlert Athena Refresh"
  runtime       = "python2.7"
  role          = "${aws_iam_role.athena_partition_role.arn}"
  handler       = "${var.lambda_handler}"
  memory_size   = "${var.lambda_memory}"
  timeout       = "${var.lambda_timeout}"
  s3_bucket     = "${var.lambda_s3_bucket}"
  s3_key        = "${var.lambda_s3_key}"

  environment {
    variables = {
      LOGGER_LEVEL   = "${var.lambda_log_level}"
      ENABLE_METRICS = "${var.enable_metrics}"
    }
  }

  tags {
    Name = "StreamAlert"
  }
}

// Lambda Alias: Rule Processor Production
resource "aws_lambda_alias" "athena_partition_refresh_production" {
  name             = "production"
  description      = "Production StreamAlert Athena Parition Refresh Alias"
  function_name    = "${aws_lambda_function.athena_partition_refresh.arn}"
  function_version = "${var.current_version}"
}

// SQS Queue: Athena Data Bucket Notificaitons
resource "aws_sqs_queue" "streamalert_athena_data_bucket_notifications" {
  name = "streamalert_athena_data_bucket_notifications"

  # Enables SQS Long Polling: https://amzn.to/2wn10CR
  receive_wait_time_seconds = 10

  # The amount of time messages are hidden after being received from a consumer
  visibility_timeout_seconds = "${format("%d", var.lambda_timeout + 2)}"

  # Retain messages for one day
  message_retention_seconds = 86400

  tags {
    Name = "StreamAlert"
  }
}

// SQS Queue Policy: Allow data buckets to send SQS messages
resource "aws_sqs_queue_policy" "streamalert_athena_data_bucket_notifications" {
  queue_url = "${aws_sqs_queue.streamalert_athena_data_bucket_notifications.id}"
  policy    = "${data.aws_iam_policy_document.athena_data_bucket_sqs_sendmessage.json}"
}

// Lambda Permission: Allow Cloudwatch Scheduled Events to invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch_events_invocation" {
  statement_id  = "CloudwatchEventsInvokeAthenaRefresh"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.athena_partition_refresh.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.invoke_athena_refresh.arn}"
  qualifier     = "production"

  depends_on = ["aws_lambda_alias.athena_partition_refresh_production"]
}

// Cloudwatch Event Rule: Invoke the Athena function refresh every minute
resource "aws_cloudwatch_event_rule" "invoke_athena_refresh" {
  name        = "streamalert_invoke_athena_refresh"
  description = "Invoke the Athena Refresh Lambda function every minute"

  # https://amzn.to/2u5t0hS
  schedule_expression = "${var.refresh_interval}"
}

// Cloudwatch Event Target: Point the Athena refresh rule to the Lambda function
resource "aws_cloudwatch_event_target" "athena_lambda_function" {
  rule = "${aws_cloudwatch_event_rule.invoke_athena_refresh.name}"
  arn  = "${aws_lambda_function.athena_partition_refresh.arn}:production"

  depends_on = ["aws_lambda_alias.athena_partition_refresh_production"]
}

// S3 Bucekt Notificaiton: Configure S3 to notify Lambda
resource "aws_s3_bucket_notification" "bucket_notification" {
  count  = "${length(var.athena_data_buckets)}"
  bucket = "${element(var.athena_data_buckets, count.index)}"

  queue {
    queue_arn = "${aws_sqs_queue.streamalert_athena_data_bucket_notifications.arn}"
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = ["aws_sqs_queue_policy.streamalert_athena_data_bucket_notifications"]
}

// Log Retention Policy
resource "aws_cloudwatch_log_group" "athena" {
  name              = "/aws/lambda/${var.prefix}_streamalert_athena_partition_refresh"
  retention_in_days = 60
}

// CloudWatch metric filters for the athena partition refresh function
// The split list is made up of: <filter_name>, <filter_pattern>, <value>
resource "aws_cloudwatch_log_metric_filter" "athena_partition_refresh_cw_metric_filters" {
  count          = "${length(var.athena_metric_filters)}"
  name           = "${element(split(",", var.athena_metric_filters[count.index]), 0)}"
  pattern        = "${element(split(",", var.athena_metric_filters[count.index]), 1)}"
  log_group_name = "${aws_cloudwatch_log_group.athena.name}"

  metric_transformation {
    name      = "${element(split(",", var.athena_metric_filters[count.index]), 0)}"
    namespace = "${var.namespace}"
    value     = "${element(split(",", var.athena_metric_filters[count.index]), 2)}"
  }
}
