/*
 * CloudWatch schedules
 */
resource "aws_cloudwatch_event_rule" "event" {
  count = length(var.query_packs)

  name                = "${var.prefix}_streamalert_scheduled_queries_event_${count.index}"
  description         = var.query_packs[count.index].description
  schedule_expression = var.query_packs[count.index].schedule_expression

  tags = {
    Name = "StreamAlert"
  }
}

resource "aws_cloudwatch_event_target" "run_step_function" {
  count = length(var.query_packs)

  rule     = aws_cloudwatch_event_rule.event[count.index].name
  arn      = aws_sfn_state_machine.state_machine.id
  role_arn = aws_iam_role.iam_for_cloudwatch_schedule.arn

  /*
   * The input transformer takes the CloudWatch event, which looks something like this...
   *   {
   *     "version": "0",
   *     "id": "91190ee0-a078-9c42-15b6-f3d418fae67d",
   *     "detail-type": "Scheduled Event",
   *     "source": "aws.events",
   *     "account": "123456789012",
   *     "time": "2019-06-14T18:39:21Z",
   *     "region": "us-east-1",
   *     "resources": [
   *       "arn:aws:events:us-east-1:123456789012:rule/something_streamalert_schedule_hourly"
   *     ],
   *     "detail": {}
   *   }
   *
   * And transforms it into something more like this:
   *   {
   *     "name": "streamalert_scheduled_queries_cloudwatch_trigger",
   *     "event_id": "9119abcd-abcd-abcd-abcd-f3d418fae67d",
   *     "source_arn": "arn:aws:events:us-east-1:123456789012:rule/something_streamalert_scheduled_queries",
   *     "function_start_time": "2019-06-14T18:39:21Z",
   *     "tags": ["tag1", "tag2"]
   *   }
   */
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
