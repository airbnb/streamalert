# Stream Alert Kinesis Terraform Module
* This Terraform module creates the following:
  * A Kinesis Stream to send logs to for rule matching against the StreamAlert lambda function.
  * A Kinesis Firehose for long term log storage in S3.

## Components
* Create a Kinesis Stream
* Create a Kinesis Firehose
* Create a user to send to the stream
* Create roles/policies for the user account
* Create a role to allow the Firehose to send to the provided S3 bucket

## Example
```
module "kinesis" {
  source                  = "../modules/tf_stream_alert_kinesis"
  account_id              = "${var.account_id}"
  region                  = "${var.region}"
  firehose_s3_bucket_name = "${var.firehose_s3_bucket_name}"
  firehose_s3_bucket_arn  = "${module.kinesis_s3.arn}"
}
```

## Inputs
* Before tuning settings for the Kinesis Stream or Kinesis Firehose, please read the following documentation:
  * http://docs.aws.amazon.com/streams/latest/dev/key-concepts.html
  * http://docs.aws.amazon.com/firehose/latest/dev/what-is-this-service.html

<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>account_id</td>
    <td>Your AWS Account ID</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>region</td>
    <td>The AWS region for your stream</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>firehose_s3_bucket_name</td>
    <td>The name of the S3 bucket to store logs emitted to Kinesis Firehose</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>firehose_s3_bucket_arn</td>
    <td>The ARN of the S3 bucket to store logs emitted to Kinesis Firehose</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>firehose_name</td>
    <td>The name for the Kinesis Firehose</td>
    <td>stream_alert_firehose</td>
    <td>False</td>
  </tr>
  <tr>
    <td>firehose_log_group</td>
    <td>The log group for Kinesis Firehose cloudwatch logs</td>
    <td>/aws/kinesisfirehose/stream_alert</td>
    <td>False</td>
  </tr>
  <tr>
    <td>stream_name</td>
    <td>The name of the Kinesis Stream</td>
    <td>stream_alert_stream</td>
    <td>False</td>
  </tr>
  <tr>
    <td>stream_shards</td>
    <td>The number of shards in the Kinesis Stream</td>
    <td>2</td>
    <td>False</td>
  </tr>
  <tr>
    <td>stream_retention</td>
    <td>The number of hours to retain data in the Kinesis Stream</td>
    <td>24</td>
    <td>False</td>
  </tr>
</table>

## Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>arn</td>
    <td>The ARN of the Kinesis Stream</td>
  </tr>
</table>
