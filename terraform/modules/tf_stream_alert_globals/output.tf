output "rules_table_arn" {
  value = "${element(concat(aws_dynamodb_table.rules_table.*.arn, list("")), 0)}"
}
