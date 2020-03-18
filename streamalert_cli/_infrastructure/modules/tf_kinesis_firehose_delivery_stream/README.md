# StreamAlert Kinesis Firehose Delivery Stream Module

* This Terraform module creates the following:
  * A Firehose Delivery Stream for each configured log type
  * An S3 bucket to store data sent through each Delivery Stream

## Example
```
module "kinesis_firehose" {
  source                  = "../modules/tf_kinesis_firehose_delivery_stream"
  account_id              = "111111222222"
  region                  = "us-east-1"
  use_prefix              = true
  prefix                  = "my-company"
  logs                    = ["json_data", "csv_data"]
  s3_bucket_name          = "my-data-bucket.id"
  s3_logging_bucket       = "my-logging-bucket.id"
}
```

## Inputs
* Before tuning settings for Kinesis Firehose, please read the following documentation:
  * http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html
  * https://www.terraform.io/docs/providers/aws/r/kinesis_firehose_delivery_stream.html

<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default</th>
    <th>Required</th>
  </tr>
  <tr>
    <td>buffer_size</td>
    <td>The amount of buffered incoming data before delivering it to Amazon S3</td>
    <td>5 (MB)</td>
    <td>False</td>
  </tr>
  <tr>
    <td>buffer_interval</td>
    <td>The frequency of data delivery to Amazon S3</td>
    <td>300 (seconds)</td>
    <td>False</td>
  </tr>
  <tr>
    <td>log_name</td>
    <td>The list of log types to create corresponding Firehose Delivery Streams for</td>
    <td></td>
    <td>True</td>
  </tr>
  <tr>
    <td>s3_bucket_name</td>
    <td>The name of the S3 bucket to store logs emitted from Kinesis Firehose</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>compression_format</td>
    <td>The compression algorithm to use on data stored in S3</td>
    <td>Snappy</td>
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
    <td>data_bucket_arn</td>
    <td>The ARN of the configured data bucket</td>
  </tr>
</table>
