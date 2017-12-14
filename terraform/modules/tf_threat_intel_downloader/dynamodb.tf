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

// IAM Role: Application autoscalling role
resource "aws_iam_role" "appautoscaling" {
  count              = "${var.autoscale ? 1 : 0}"
  name               = "${var.prefix}_streamalert_appautoscaling"
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
resource "aws_iam_role_policy" "appautoscaling" {
  count  = "${var.autoscale ? 1 : 0}"
  name   = "DynamoDBAppAutoscalePolicy"
  role   = "${aws_iam_role.appautoscaling.id}"
  policy = "${data.aws_iam_policy_document.appautoscaling.json}"
}

// IAM Policy Doc: Allow autoscaling IAM role to send alarm to CloudWatch
// and change table settings for autoscaling.
data "aws_iam_policy_document" "appautoscaling" {
  count = "${var.autoscale ? 1 : 0}"

  statement {
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateTable",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:SetAlarmState",
      "cloudwatch:DeleteAlarms",
    ]

    resources = [
      "${aws_dynamodb_table.threat_intel_ioc.arn}",
      "${aws_cloudwatch_log_group.threat_intel_downloader.arn}",
    ]
  }
}

resource "aws_appautoscaling_target" "dynamodb_table_read_target" {
  count              = "${var.autoscale ? 1 : 0}"
  max_capacity       = 100
  min_capacity       = 5
  resource_id        = "${var.prefix}_streamalert_threat_intel_downloader"
  role_arn           = "${aws_iam_role.appautoscaling.arn}"
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

    # Utilization remains at or near 70%
    target_value = 70
  }
}
