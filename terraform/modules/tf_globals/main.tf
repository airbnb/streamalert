module "alerts_firehose" {
  source      = "./alerts_firehose"
  account_id  = var.account_id
  prefix      = var.prefix
  region      = var.region
  kms_key_arn = var.kms_key_arn
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
