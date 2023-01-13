// Note: When creating cross-account log destinations, the destination must
//       be in the same AWS region as the log group that is sending it data.
//       However, the AWS resource that the destination points to can be
//       located in a different region.
// Source: http://amzn.to/2zF7CS0

# This is here to remove a warning in the deployment
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = ">= 4.0.0, < 4.9.0"
    }
  }
}

resource "aws_cloudwatch_log_destination" "cloudwatch_to_kinesis" {
  name       = "${var.prefix}_${var.cluster}_streamalert_log_destination"
  role_arn   = var.cloudwatch_logs_subscription_role_arn
  target_arn = var.destination_kinesis_stream_arn
}

resource "aws_cloudwatch_log_destination_policy" "cloudwatch_to_kinesis" {
  destination_name = aws_cloudwatch_log_destination.cloudwatch_to_kinesis.name
  access_policy    = data.aws_iam_policy_document.cloudwatch_logs_destination_policy.json
}
