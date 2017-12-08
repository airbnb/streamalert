resource "aws_dynamodb_table" "threat_intel_ioc" {
  name           = "${var.prefix}_streamalert_threat_intel_downloader"
  read_capacity  = "${var.table_rcu}"
  write_capacity = "${var.table_wcu}"
  hash_key       = "ioc_value"

  attribute {
    name = "ioc_value"
    type = "S"
  }

  ttl {
    attribute_name = "expiration_date"
    enabled        = true
  }

  tags {
    Name = "StreamAlert"
  }
}
