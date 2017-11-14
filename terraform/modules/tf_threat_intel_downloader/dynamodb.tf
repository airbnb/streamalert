resource "aws_dynamodb_table" "threat_intel_ioc" {
  name           = "${var.table_name}"
  read_capacity  = "${var.table_rcu}"
  write_capacity = "${var.table_wcu}"
  hash_key       = "value"
  range_key      = "type"

  attribute {
    name = "value"
    type = "S"
  }

  attribute {
    name = "type"
    type = "S"
  }

  ttl {
    attribute_name = "expiration_date"
    enabled        = true
  }

  tags {
    Name = "ThreatIntel"
  }
}
