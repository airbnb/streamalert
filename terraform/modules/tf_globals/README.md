# StreamAlert Globals
* This Terraform module creates various global infrastructure components

## Components
* Kinesis Firehose Delivery Stream for Putting Alerts on S3

## Example
```
module "globals" {
  source                       = "../modules/tf_globals"
  account_id                   = "112233445566"
  region                       = "us-east-1"
  prefix                       = "mycompany"
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
  <tr>
    <td>prefix</td>
    <td>The resource prefix, normally an organizational name or descriptor</td>
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
