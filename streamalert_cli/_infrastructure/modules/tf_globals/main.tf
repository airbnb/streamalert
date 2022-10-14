module "alerts_firehose" {
  source                   = "./alerts_firehose"
  account_id               = var.account_id
  prefix                   = var.prefix
  region                   = var.region
  buffer_size              = var.alerts_firehose_buffer_size
  buffer_interval          = var.alerts_firehose_buffer_interval
  cloudwatch_log_retention = var.alerts_firehose_cloudwatch_log_retention
  kms_key_arn              = var.kms_key_arn
  bucket_name              = var.alerts_firehose_bucket_name == "" ? "${var.prefix}-streamalerts" : var.alerts_firehose_bucket_name
  alerts_db_name           = var.alerts_db_name
  file_format              = var.alerts_file_format
  alerts_schema            = var.alerts_schema
}

module "classifier_queue" {
  source               = "./classifier_queue"
  account_id           = var.account_id
  prefix               = var.prefix
  region               = var.region
  rules_engine_timeout = var.rules_engine_timeout
  use_prefix           = var.sqs_use_prefix
}

// TODO: Autoscaling
resource "aws_dynamodb_table" "alerts_table" {
  name           = "${var.prefix}_streamalert_alerts"
  read_capacity  = var.alerts_table_read_capacity
  write_capacity = var.alerts_table_write_capacity
  hash_key       = "RuleName"
  range_key      = "AlertID"

  // Only the hash key and range key attributes need to be defined here.
  attribute {
    name = "RuleName"
    type = "S"
  }

  attribute {
    name = "AlertID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "StreamAlert"
  }
}

// DynamoDB table to store some rule information
resource "aws_dynamodb_table" "rules_table" {
  count          = var.enable_rule_staging ? 1 : 0
  name           = "${var.prefix}_streamalert_rules"
  read_capacity  = var.rules_table_read_capacity
  write_capacity = var.rules_table_write_capacity
  hash_key       = "RuleName"

  attribute {
    name = "RuleName"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "StreamAlert"
  }
}

resource "aws_lambda_layer_version" "aliyun_dependencies" {
  filename            = "${path.module}/lambda_layers/aliyun-python-sdk-actiontrail==2.0.0_dependencies.zip"
  layer_name          = "aliyun"
  compatible_runtimes = ["python3.9"]
}

resource "aws_lambda_layer_version" "box_dependencies" {
  filename            = "${path.module}/lambda_layers/boxsdk[jwt]==2.9.0_dependencies.zip"
  layer_name          = "box"
  compatible_runtimes = ["python3.9"]
}
