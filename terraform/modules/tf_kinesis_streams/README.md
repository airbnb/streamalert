# StreamAlert Kinesis Terraform Module

* This Terraform module creates the following:
  * A Kinesis Stream to send logs to for rule matching against the StreamAlert lambda function.

## Example
```
module "kinesis" {
  source                  = "../modules/tf_kinesis_streams"
  account_id              = "333333444444"
  region                  = "us-east-1"
  prefix                  = "company-name"
  cluster                 = "cluster-name"
  stream_name             = "name-for-kinesis-stream"
  shards                  = 10
  retention               = 72
}
```

## Inputs
* Before tuning settings for the Kinesis Stream, please read the following documentation:
  * http://docs.aws.amazon.com/streams/latest/dev/key-concepts.html

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
    <td>cluster</td>
    <td>The StreamAlert cluster name</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>stream_name</td>
    <td>The name of the Kinesis Stream</td>
    <td>None</td>
    <td>True</td>
  </tr>
  <tr>
    <td>shards</td>
    <td>The number of shards in the Kinesis Stream</td>
    <td>2</td>
    <td>False</td>
  </tr>
  <tr>
    <td>retention</td>
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
