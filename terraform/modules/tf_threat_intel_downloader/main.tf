// Lambda function: Threat Intel Downloader
// It retrieves IOCs and stores them in DynamoDB table
resource "aws_lambda_function" "threat_intel_downloader" {
  function_name = "${var.prefix}_streamalert_threat_intel_downloader"
  description   = "StreamAlert Threat Intel Downloader"
  runtime       = "python3.7"
  role          = aws_iam_role.threat_intel_downloader.arn
  handler       = var.lambda_handler
  memory_size   = var.lambda_memory
  timeout       = var.lambda_timeout

  filename         = var.filename
  source_code_hash = filebase64sha256(var.filename)
  publish          = true

  environment {
    variables = {
      LOGGER_LEVEL   = var.lambda_log_level
      ENABLE_METRICS = var.enable_metrics
    }
  }

  dead_letter_config {
    target_arn = "arn:aws:sns:${var.region}:${var.account_id}:${var.monitoring_sns_topic}"
  }

  tags = {
    Name    = "StreamAlert"
    AltName = "ThreatIntel"
  }
}

// Lambda Alias: Threat Intel Downloader Production
resource "aws_lambda_alias" "production" {
  name             = "production"
  description      = "Production Threat Intel Dowwnloader Alias"
  function_name    = aws_lambda_function.threat_intel_downloader.arn
  function_version = aws_lambda_function.threat_intel_downloader.version
}

// Lambda Permission: Allow Cloudwatch Scheduled Events to invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch_events_invocation" {
  statement_id  = "CloudwatchEventsInvokeThreatIntelDownloader"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel_downloader.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.invoke_threat_intel_downloader.arn
  qualifier     = "production"

  # explicit dependency
  depends_on = [aws_lambda_alias.production]
}

// Cloudwatch Event Rule: Invoke the threat_intel_downloader once a day
resource "aws_cloudwatch_event_rule" "invoke_threat_intel_downloader" {
  name        = "${var.prefix}_streamalert_invoke_threat_intel_downloader"
  description = "Invoke the Threat Intel Downloader Lambda function periodically"

  # https://amzn.to/2u5t0hS
  schedule_expression = var.interval

  tags = {
    Name    = "StreamAlert"
    AltName = "ThreatIntel"
  }
}

// Cloudwatch Event Target: Point the threat intel downloader rule to the Lambda function
resource "aws_cloudwatch_event_target" "threat_intel_downloader_lambda_function" {
  rule = aws_cloudwatch_event_rule.invoke_threat_intel_downloader.name
  arn  = "${aws_lambda_function.threat_intel_downloader.arn}:production"

  # explicit dependency
  depends_on = [aws_lambda_alias.production]
}

// Log Retention Policy: lambda function
resource "aws_cloudwatch_log_group" "threat_intel_downloader" {
  name              = "/aws/lambda/${aws_lambda_function.threat_intel_downloader.function_name}"
  retention_in_days = var.log_retention

  tags = {
    Name    = "StreamAlert"
    AltName = "ThreatIntel"
  }
}
