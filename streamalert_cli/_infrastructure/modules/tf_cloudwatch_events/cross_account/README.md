# StreamAlert CloudWatch Events Cross Account Terraform Module
Configure the necessary resources to allow for cross account CloudWatch Events via EventBridge Events Bus

## Components
* Configures CloudWatch Event Permissions to allow external accounts or organizations to send events to the main account

## Example
```hcl
module "cloudwatch_events_cross_account" {
  source            = "./modules/tf_cloudwatch_events/cross_account"
  organization_ids  = ["123456789012"]
  org_ids           = ["o-aabbccddee"]
  region            = "us-east-1"
}
```

## Inputs
<table>
  <tr>
    <th>Property</th>
    <th>Description</th>
    <th>Default (None=Required)</th>
  </tr>
  <tr>
    <td>account_ids</td>
    <td>AWS Account IDs for which to enable cross account CloudWatch Events</td>
    <td>None</td>
  </tr>
  <tr>
    <td>organization_ids</td>
    <td>AWS Organization IDs for which to enable cross account CloudWatch Events</td>
    <td>None</td>
  </tr>
  <tr>
    <td>region</td>
    <td>AWS region in which this permission is being added</td>
    <td>None</td>
  </tr>
</table>
