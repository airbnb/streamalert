Pagerduty
* format: https://events.pagerduty.com/generic/2010-04-15/create_event.json,integration-key
* create a temporary text file with the contents above (no newline at the end)
* run the following command:

aws kms encrypt \
--region us-east-1 \
--key-id alias/stream_alert_secrets \
--plaintext fileb://<tmp-credential-filepath> \
--query CiphertextBlob --output text | base64 -D > stream_alert_output/encrypted_credentials/pagerduty

Slack
* format: baseurl,token (split after services/)
https://hooks.slack.com/services,token

aws kms encrypt \
--region us-east-1 \
--key-id alias/stream_alert_secrets \
--plaintext fileb://<tmp-credential-filepath> \
--query CiphertextBlob --output text | base64 -D > stream_alert_output/encrypted_credentials/slack

* deploy link