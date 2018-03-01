Webhook
=======

Overview
--------

StreamAlert can be receive webhooks as input by setting up AWS API Gateway.
Services such as Canary Tools that can trigger a webhook can use this to feed
into StreamAlert, resulting a StreamAlert rules being triggered.
You will need to manually setup the API Gateway, which will will provide you
with a URL that you can use as the webhook URL for the service.
Once a request is made to this URL, a record will be posted to the Kinesis
Stream monitored by StreamAlert.

Setting up the IAM role
-----------------------

.. code-block:: bash
  :caption: `Commands to set up the IAM role`
  cat << EOF > assume_role.json
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                  "Service": "apigateway.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
          }
      ]
  }
  EOF

  aws iam create-role --role-name StreamWriter --assume-role-policy-document file://assume_role.json --description "Allows API Gateway to write to Kinesis"

  aws iam attach-role-policy --role-name StreamWriter --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"

  cat << EOF > AllowPutRecord.json
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "kinesis:PutRecord"
              ],
              "Resource": "*"
          }
      ]
  }
  EOF

  aws iam put-role-policy --role-name StreamWriter --policy-name AllowPutRecord --policy-document file://AllowPutRecord.json

Creating the webhook
--------------------

.. code-block:: bash
  :caption: `Create the rest api`
  aws apigateway create-rest-api --name StreamWriter --description "Webhook that writes to the Kinesis Stream for StreamAlert" --endpoint-configuration types=REGIONAL


This will return an API_ID, such as 4xmqlj1659, that you will need in future
commands.

.. code-block:: json
  :caption: `Sample output from create-rest-api`
  {
      "id": "API_ID",
      "name": "StreamWriter",
      "description": "Webhook that writes to the Kinesis Stream for StreamAlert",
      "createdDate": 1519762634,
      "apiKeySource": "HEADER",
      "endpointConfiguration": {
          "types": [
              "REGIONAL"
          ]
      }
  }

Use that API_ID to find the id of resource created, which we'll call the
PARENT_ID:

.. code-block:: bash
  :caption: `Get the id of the resource`
  aws apigateway get-resources --rest-api-id API_ID

.. code-block:: json
  :caption: `Sample output from get-resources`
  {
      "items": [
          {
              "id": "PARENT_ID",
              "path": "/"
          }
      ]
  }

Use the API_ID and the PARENT_ID to create a new resource that is used as the
URL path on this domain for the webhook. In this case I'm using
"mysecrethook".

.. code-block:: bash
  :caption: `Create the webhook`
  aws apigateway create-resource --rest-api-id API_ID --parent-id PARENT_ID --path-part mysecrethook

Use the RESOURCE_ID returned by this:

.. code-block:: bash
  :caption: `Configure the webhook`
  aws apigateway put-method-response --rest-api-id API_ID --resource-id RESOURCE_ID --http-method POST --status-code 200 --response-models '{"application/json": "Empty"}'

  aws apigateway put-integration-response --rest-api-id API_ID --resource-id RESOURCE_ID --http-method POST --status-code 200 --response-templates '{"application/json":""}' 

  cat << EOF > requestTemplate.json
  { 
      "application/json": "{\n    \"Data\": \"\$util.base64Encode(\"{\"\"webhookApiId\"\": \"\"\$context.apiId\"\", \"\"url\"\": \"\"\$context.path\"\", \"\"sourceIp\"\":\"\"\$context.identity.sourceIp\"\", \"\"userAgent\"\":\"\"\$context.identity.userAgent\"\", \"\"requestTime\"\":\"\"\$context.requestTime\"\", \"\"querystring\"\":\"\"\$util.urlDecode(\$input.params().querystring)\"\",\"\"detail\"\":\$input.json('$')}\")\",\n    \"PartitionKey\": \"0\",\n    \"StreamName\": \"test_prod_stream_alert_kinesis\"\n}"
  }
  EOF

  aws apigateway put-integration \
      --rest-api-id API_ID \
      --resource-id RESOURCE_ID \
      --http-method POST \
      --integration-http-method POST \
      --type AWS \
      --uri "arn:aws:apigateway:us-east-1:kinesis:action/PutRecord" \
      --credentials "arn:aws:iam::ACCOUNT_ID:role/StreamWriter" \
      --request-templates file://requestTemplate.json \
      --passthrough-behavior NEVER


  # Then, only after you've done the above, create the deployment
  aws apigateway create-deployment --rest-api-id API_ID --stage-name deployed

You will now able to trigger your webhook by POST'ing to:
https://API_ID.execute-api.us-east-1.amazonaws.com/deployed/mysecrethook

