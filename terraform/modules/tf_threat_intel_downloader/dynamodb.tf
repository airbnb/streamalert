resource "aws_dynamodb_table" "threat_intel_ioc" {
  name           = "${var.prefix}_streamalert_threat_intel_downloader"
  read_capacity  = var.table_rcu
  write_capacity = var.table_wcu
  hash_key       = "ioc_value"

  attribute {
    name = "ioc_value"
    type = "S"
  }

  # It is recommended to use lifecycle ignore_changes for read_capacity and/or
  # write_capacity if there's autoscaling policy attached to the table. We have
  # autoscaling policy for read_capacity
  lifecycle {
    ignore_changes = [read_capacity]
  }

  ttl {
    attribute_name = "expiration_ts"
    enabled        = true
  }

  tags = {
    Name    = "StreamAlert"
    AltName = "ThreatIntel"
  }
}

resource "aws_appautoscaling_target" "dynamodb_table_read_target" {
  max_capacity       = var.max_read_capacity
  min_capacity       = var.min_read_capacity
  resource_id        = "table/${aws_dynamodb_table.threat_intel_ioc.name}"
  role_arn           = "arn:aws:iam::${var.account_id}:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "dynamodb_table_read_policy" {
  name               = "DynamoDBReadCapacityUtilization:${aws_appautoscaling_target.dynamodb_table_read_target.resource_id}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.dynamodb_table_read_target.resource_id
  scalable_dimension = aws_appautoscaling_target.dynamodb_table_read_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.dynamodb_table_read_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }

    # Utilization remains at or near 70% (default)
    target_value = var.target_utilization
  }
}
