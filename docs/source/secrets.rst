Secrets
=======

Create a new CMK
----------------

You will need to create a customer master key(CMK) so you can use the IAM section of the AWS Management Console.

``http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html``

Pagerduty
---------

Create a temporary file with the contents:

``https://events.pagerduty.com/generic/2010-04-15/create_event.json,YOUR-INTEGRATION-KEY-HERE``

Run the following command::

  aws kms encrypt \
  --region us-east-1 \
  --key-id alias/stream_alert_secrets \
  --plaintext fileb://<tmp-credential-filepath> \
  --query CiphertextBlob --output text | base64 -D > stream_alert_output/encrypted_credentials/pagerduty

Slack
-----

Create a temporary file with the contents:

``https://hooks.slack.com/services,YOUR-TOKEN-HERE``

Run the following::

  aws kms encrypt \
  --region us-east-1 \
  --key-id alias/stream_alert_secrets \
  --plaintext fileb://<tmp-credential-filepath> \
  --query CiphertextBlob --output text | base64 -D > stream_alert_output/encrypted_credentials/slack

