// IAM Role: CloudWatch Events
resource "aws_iam_role" "cloudwatch_events_role" {
  name               = "${var.prefix}_${var.cluster}_cloudwatch_events_role"
  path               = "/streamalert/"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_events_role_assume_role_policy.json

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

data "aws_iam_policy_document" "cloudwatch_events_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

// IAM Policy: Allow CloudWatch to write events to Kinesis Streams
resource "aws_iam_role_policy" "cloudwatch_events_policy" {
  name   = "CloudWatchEventsToKinesis"
  role   = aws_iam_role.cloudwatch_events_role.id
  policy = data.aws_iam_policy_document.kinesis_put_records.json
}

data "aws_iam_policy_document" "kinesis_put_records" {

  statement {
    sid = "CloudWatchEventsPutKinesisRecords"

    actions = [
      "kinesis:PutRecord",
      "kinesis:PutRecords",
    ]

    resources = [
      var.kinesis_arn,
    ]
  }
}


// CloudFormation Stack to substitute for this limitation in Terraform:
//   https://github.com/terraform-providers/terraform-provider-aws/issues/8759
//
// This stack creates a rule in EventBridge (vs CloudWatch Events) since Terraform currently
// does not support apply this directly. EventBridge is needed for this rule, because content-based
// filtering with Event Patterns is not a supported feature in the "legacy" aws_cloudwatch_event_rule
// See here:
//   https://docs.aws.amazon.com/eventbridge/latest/userguide/content-filtering-with-event-patterns.html#filtering-anything-but-matching-example
//
// The aws_cloudwatch_event_rule event patterns only support strings, or list of strings, vs the more
// advanced mapping with things like "anything-but". Once this is supported by Terraform, this stack
// can be removed and the below code uncommented to be applied.
resource "aws_cloudformation_stack" "eventbridge_rule" {
  name = "CloudWatchEvents${var.prefix}${var.cluster}StreamAlert"

  // Ideally, the AWS::Events::Rule resource would also be tagged here. However, it appears that
  // while the resource itself supports tagging, CloudFormation does not in fact support it for
  // this resource type...
  template_body = <<EOF
Resources:
  ${var.prefix}${var.cluster}StreamAlertEventBridgeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: "${var.prefix}_${var.cluster}_streamalert_all_events"
      Description: "Capture CloudWatch events"
      EventPattern: "${var.event_pattern}"
      RoleArn: "${aws_iam_role.cloudwatch_events_role.arn}"
      Targets:
        - Arn: "${var.kinesis_arn}"
          Id: "${var.prefix}_${var.cluster}_streamalert_kinesis"
          RoleArn: "${aws_iam_role.cloudwatch_events_role.arn}"
EOF

  tags = {
    Name    = "StreamAlert"
    Cluster = var.cluster
  }
}

// Uncomment the below when it is properly supported by Terraform, and remove the above stack
########################################################
########################################################
################# KEEP FOR FUTURE USE ##################
########################################################
########################################################
// Cloudwatch Event Rule: Capture CloudWatch Events
# resource "aws_cloudwatch_event_rule" "capture_events" {
#   name          = "${var.prefix}_${var.cluster}_streamalert_all_events"
#   description   = "Capture CloudWatch events"
#   role_arn      = aws_iam_role.cloudwatch_events_role.arn
#   event_pattern = var.event_pattern
#
#   tags = {
#     Name    = "StreamAlert"
#     Cluster = var.cluster
#   }
# }
#
// The Kinesis destination for Cloudwatch events
# resource "aws_cloudwatch_event_target" "kinesis" {
#   rule = aws_cloudwatch_event_rule.capture_events.name
#   arn  = var.kinesis_arn
# }
########################################################
########################################################
################# KEEP FOR FUTURE USE ##################
########################################################
########################################################
