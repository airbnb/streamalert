module "alerts_firehose" {
  source     = "alerts_firehose"
  account_id = "${var.account_id}"
  prefix     = "${var.prefix}"
  region     = "${var.region}"
}

// TODO: Autoscaling
resource "aws_dynamodb_table" "alerts_table" {
  name           = "${var.prefix}_streamalert_alerts"
  read_capacity  = "${var.alerts_table_read_capacity}"
  write_capacity = "${var.alerts_table_write_capacity}"
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
  tags {
    Name = "StreamAlert"
  }
}

// DynamoDB table to store some rule information
resource "aws_dynamodb_table" "rules_table" {
  name           = "${var.prefix}_streamalert_rules"
  read_capacity  = "${var.rules_table_read_capacity}"
  write_capacity = "${var.rules_table_write_capacity}"
  hash_key       = "RuleName"

  attribute {
    name = "RuleName"
    type = "S"
  }

  tags {
    Name = "StreamAlert"
  }
}
