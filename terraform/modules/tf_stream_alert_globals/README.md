# Stream Alert Globals
* This Terraform module creates various global infrastructure components

## Components
* Kinesis Firehose Delivery Stream for Putting Alerts on S3

## Example
```
module "stream_alert" {
  source                       = "../modules/tf_stream_alert"
  account_id                   = "112233445566"
  region                       = "us-east-1"
  lambda_source_bucket_name    = "mycompany.streamalert.source"
  lambda_source_key            = "/source/stream_alert_v1.0"
  lambda_function_prod_version = "$LATEST"
  lambda_handler               = "main.lambda_handler"
}
```

## Inputs
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
</table>

## Outputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
  </tr>
</table>
