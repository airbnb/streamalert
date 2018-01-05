resource "aws_dynamodb_table" "threat_intel_ioc" {
  name           = "${var.prefix}_streamalert_threat_intel_downloader"
  read_capacity  = "${var.table_rcu}"
  write_capacity = "${var.table_wcu}"
  hash_key       = "ioc_value"

  attribute {
    name = "ioc_value"
    type = "S"
  }

  # It is recommended to use lifecycle ignore_changes for read_capacity and/or
  # write_capacity if there's autoscaling policy attached to the table. We have
  # autoscaling policy for read_capacity
  lifecycle {
    ignore_changes = ["read_capacity"]
  }

  ttl {
    attribute_name = "expiration_ts"
    enabled        = true
  }

  tags {
    Name = "StreamAlert"
  }
}

// IAM Role: Application autoscalling role
resource "aws_iam_role" "stream_alert_dynamodb_appautoscaling" {
  count              = "${var.autoscale ? 1 : 0}"
  name               = "${var.prefix}_streamalert_dynamodb_appautoscaling"
  assume_role_policy = "${data.aws_iam_policy_document.appautoscaling_assume_role_policy.json}"
}

// IAM Policy Doc: Generic Application Autoscaling AssumeRole
data "aws_iam_policy_document" "appautoscaling_assume_role_policy" {
  count = "${var.autoscale ? 1 : 0}"

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["application-autoscaling.amazonaws.com"]
    }
  }
}

// IAM Role Policy: Allow appautoscaling IAM role to autoscaling DynamoDB table
resource "aws_iam_role_policy" "appautoscaling_update_table" {
  count  = "${var.autoscale ? 1 : 0}"
  name   = "DynamoDBAppAutoscaleUpdateTablePolicy"
  role   = "${aws_iam_role.stream_alert_dynamodb_appautoscaling.id}"
  policy = "${data.aws_iam_policy_document.appautoscaling_update_table.json}"
}

// IAM Policy Doc: Allow autoscaling IAM role to send alarm to CloudWatch
// and change table settings for autoscaling.
// This policy is allow the role to change table settings
data "aws_iam_policy_document" "appautoscaling_update_table" {
  count = "${var.autoscale ? 1 : 0}"

  statement {
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateTable",
    ]

    resources = [
      "${aws_dynamodb_table.threat_intel_ioc.arn}",
    ]
  }
}

// IAM Role Policy: Allow appautoscaling IAM role to autoscaling DynamoDB table
resource "aws_iam_role_policy" "appautoscaling_cloudwatch_alarms" {
  count  = "${var.autoscale ? 1 : 0}"
  name   = "DynamoDBAppAutoscaleCloudWatchAlarmsPolicy"
  role   = "${aws_iam_role.stream_alert_dynamodb_appautoscaling.id}"
  policy = "${data.aws_iam_policy_document.appautoscaling_cloudwatch_alarms.json}"
}

// IAM Policy Doc: This policy is allow the role to send alarm to CloudWatch.
data "aws_iam_policy_document" "appautoscaling_cloudwatch_alarms" {
  count = "${var.autoscale ? 1 : 0}"

  statement {
    effect = "Allow"

    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:SetAlarmState",
      "cloudwatch:DeleteAlarms",
    ]

    resources = ["*"]
  }
}

resource "aws_appautoscaling_target" "dynamodb_table_read_target" {
  count              = "${var.autoscale ? 1 : 0}"
  max_capacity       = "${var.max_read_capacity}"
  min_capacity       = "${var.min_read_capacity}"
  resource_id        = "table/${var.prefix}_streamalert_threat_intel_downloader"
  role_arn           = "${aws_iam_role.stream_alert_dynamodb_appautoscaling.arn}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "dynamodb_table_read_policy" {
  count              = "${var.autoscale ? 1 : 0}"
  name               = "DynamoDBReadCapacityUtilization:${aws_appautoscaling_target.dynamodb_table_read_target.resource_id}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = "${aws_appautoscaling_target.dynamodb_table_read_target.resource_id}"
  scalable_dimension = "${aws_appautoscaling_target.dynamodb_table_read_target.scalable_dimension}"
  service_namespace  = "${aws_appautoscaling_target.dynamodb_table_read_target.service_namespace}"

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }

    # Utilization remains at or near 70% (default)
    target_value = "${var.target_utilization}"
  }
}
