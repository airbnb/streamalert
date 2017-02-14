'''
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import base64
import json
import os
import sys

BASEFOLDER = 'test/integration/fixtures'

def read_kinesis_records(local_directories):
    """Read raw kinesis records and format for Lambda test event.

    Args:
        local_directories (list): local_directories to read raw records from.

    Returns:
        (dict): formatted Kinesis records to be output as JSON.

    The lambda input format is line delimited JSON.
    Example Kinesis record:

    {
      "Records": [
        {
          "eventID": "shardId-000000000000:1111",
          "eventVersion": "1.0",
          "kinesis": {
            "approximateArrivalTimestamp": 1428537600,
            "partitionKey": "partitionKey-3",
            "data": "SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IDEyMy4=",
            "kinesisSchemaVersion": "1.0",
            "sequenceNumber": "1111"
          },
          "invokeIdentityArn": "arn:aws:iam::EXAMPLE",
          "eventName": "aws:kinesis:record",
          "eventSourceARN": "arn:aws:kinesis:EXAMPLE",
          "eventSource": "aws:kinesis",
          "awsRegion": "us-east-1"
        }
      ]
    }

    StreamAlert only needs the kinesis['data'], eventSource, and
    eventSourceARN keys, so we only add those to the mock record.
    """
    records = {'Records': []}
    for folder in local_directories:
        for root, _, files in os.walk(os.path.join(BASEFOLDER, folder)):
            for json_file in files:
                with open(os.path.join(root, json_file), 'r') as json_fh:
                    lines = json_fh.readlines()
                for line in lines:
                    line = line.strip()
                    record = {
                        'kinesis': {'data': base64.b64encode(line)},
                        'eventSource': 'aws:{}'.format(folder),
                        'eventSourceARN': 'arn:aws:{}:region:account-id:stream/{}' \
                            .format(folder, root.split('/')[-1])
                    }
                    records['Records'].append(record)

    return records

def read_s3_records(local_directories):
    """Read S3 event notifications and format Lambda test event.

    Args:
        local_directories (list): local_directories to read raw records from.

    Returns:
        (dict): formatted Kinesis records to be output as JSON.

    Example S3 Event Notification Record:
    {
      "eventVersion": "2.0",
      "eventTime": "1970-01-01T00:00:00.000Z",
      "requestParameters": {
        "sourceIPAddress": "127.0.0.1"
      },
      "s3": {
        "configurationId": "testConfigRule",
        "object": {
          "eTag": "0123456789abcdef0123456789abcdef",
          "sequencer": "0A1B2C3D4E5F678901",
          "key": "HappyFace.jpg",
          "size": 1024
        },
        "bucket": {
          "arn": "arn:aws:s3:::mybucket",
          "name": "sourcebucket",
          "ownerIdentity": {
            "principalId": "EXAMPLE"
          }
        },
        "s3SchemaVersion": "1.0"
      },
      "responseElements": {
        "x-amz-id-2": "EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH",
        "x-amz-request-id": "EXAMPLE123456789"
      },
      "awsRegion": "us-east-1",
      "eventName": "ObjectCreated:Put",
      "userIdentity": {
        "principalId": "EXAMPLE"
      },
      "eventSource": "aws:s3"
    }
    """
    records = {'Records': []}
    for folder in local_directories:
        for root, _, files in os.walk(os.path.join(BASEFOLDER, folder)):
            for test_file in files:
                with open(os.path.join(root, test_file), 'r') as test_file_fh:
                    lines = test_file_fh.readlines()
                for line in lines:
                    line = line.strip()
                    # provide a way to skip records
                    if line[0] == '#':
                        continue
                    record = json.loads(line)
                    # TODO(jacknagz) load this bucket from variables.json
                    record['s3']['bucket']['arn'] = 'arn:aws:s3:::my-org-name-here.streamalert.testing.results'
                    record['s3']['bucket']['name'] = 'my-org-name-here.streamalert.testing.results'
                    record['awsRegion'] = 'us-east-1'
                    record['eventName'] = 'ObjectCreated:Put'
                    records['Records'].append(record)

    return records

def format_sns(in_file):
    with open(in_file, 'r') as f:
        in_file_contents = json.load(f)

    message = base64.b64encode(json.dumps(in_file_contents))
    out_records = {
      "Records": [
          {
              "EventVersion": "1.0",
              "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
              "EventSource": "aws:sns",
              "Sns": {
                "SignatureVersion": "1",
                "Timestamp": "1970-01-01T00:00:00.000Z",
                "Signature": "EXAMPLE",
                "SigningCertUrl": "EXAMPLE",
                "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
                "Message": message,
                "MessageAttributes": {
                  "Test": {
                    "Type": "String",
                    "Value": "TestString"
                  },
                  "TestBinary": {
                    "Type": "Binary",
                    "Value": "TestBinary"
                  }
                },
                "Type": "Notification",
                "UnsubscribeUrl": "EXAMPLE",
                "TopicArn": "arn:aws:sns:EXAMPLE",
                "Subject": "TestInvoke"
              }
            }
          ]
        }
    out_file = '{}.out'.format(in_file)
    write_records(out_records, out_file)

    return out_file

def write_records(records, out_file):
    """Write all formatted records to the out_file specified as JSON.

    Args:
        records (dict): A formatted Lambda test event to be JSON dumped.
        out_file (string): A filename to write to.
    """
    json_events = json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2)
    with open(out_file, 'w') as outfile:
        outfile.write(json_events)

def stream_alert_test(options):
    def alert_emulambda(out_file):
        # context_file = os.path.join(BASEFOLDER, 'context')
        sys.argv = ['emulambda', 'main.handler', out_file, '-v']
        import emulambda
        emulambda.main()

    def output_emulambda(out_file):
        context_file = os.path.join('..', 'test', 'integration', 'context')
        sys.argv = [
            'emulambda',
            'stream_alert_output.main.handler',
            out_file,
            context_file,
            '-v'
        ]
        import emulambda
        emulambda.main()

    if options.source == 'kinesis':
        if options.func == 'alert':
            out_file = os.path.join(BASEFOLDER, 'out/kinesis_record_events.json')
            kinesis_records = read_kinesis_records(['kinesis'])
            write_records(kinesis_records, out_file)
            alert_emulambda(out_file)

        elif options.func == 'output':
            os.chdir('stream_alert_output')
            sns_record_path = os.path.join('..', BASEFOLDER, 'sns/raw_record.json')
            out_file = format_sns(sns_record_path)
            output_emulambda(out_file)
            os.chdir('..')

    elif options.source == 's3':
        if options.func == 'alert':
            out_file = os.path.join(BASEFOLDER, 'out/s3_record_events.json')
            s3_records = read_s3_records(['s3'])
            write_records(s3_records, out_file)
            alert_emulambda(out_file)
