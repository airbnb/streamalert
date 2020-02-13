# FIXME (derek.wang) Use for_each instead of count.index
# CloudWatch schedules
resource "aws_cloudwatch_event_rule" "event" {
  count = length(var.query_packs)

  name                = "${var.prefix}_streamalert_scheduled_queries_event_${count.index}"
  description         = var.query_packs[count.index].description
  schedule_expression = var.query_packs[count.index].schedule_expression
}

resource "aws_cloudwatch_event_target" "run_step_function" {
  count = length(var.query_packs)

  rule     = aws_cloudwatch_event_rule.event[count.index].name
  arn      = aws_sfn_state_machine.state_machine.id
  role_arn = aws_iam_role.iam_for_cloudwatch_schedule.arn

  input_transformer {
    input_paths = {
      time       = "$.time"
      id         = "$.id"
      source_arn = "$.resources[0]"
    }
    input_template = <<JSON
{
  "name": "streamalert_scheduled_queries_cloudwatch_trigger",
  "event_id": <id>,
  "source_arn": <source_arn>,
  "streamquery_configuration": {
    "clock": <time>,
    "tags": ["${var.query_packs[count.index].name}"]
  }
}
JSON

  }
}
