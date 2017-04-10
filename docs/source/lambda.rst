Lambda
======

Overview
--------

* StreamAlert utilizes AWS Lambda for real-time data processing and alerting
* AWS Lambda lets us run code without needing to provision or manage servers
* A Lambda function is created for each `cluster <clusters.html>`_ you define

Each StreamAlert cluster creates two Lambda functions:

* ``rule_processor``: Analyze incoming logs against rules in real time
* ``alert_processor``: Deliver alerts to designated outputs

Concepts
--------
* AWS Lambda `details`_
* AWS Lambda `faq`_
* AWS Lambda `pricing`_

.. _details: https://docs.aws.amazon.com/lambda/latest/dg/welcome.html
.. _faq: https://aws.amazon.com/lambda/faqs/
.. _pricing: https://aws.amazon.com/lambda/pricing/

Fields
------

The following configuration settings are defined in ``variables.json``

Both the ```rule_processor`` and ``alert_processor`` have the same settings.

Lambda Processor Settings
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::

  "rule_processor_config": {
      "handler": "stream_alert.rule_processor.main.handler",
      "source_bucket": "prefix.streamalert.source",
      "source_current_hash": "auto_generated_hash",
      "source_object_key": "auto_generated_s3_object_key",
      "third_party_libraries": [
          "jsonpath_rw",
          "netaddr"
      ]
  },
  "rule_processor_lambda_config": {
      "prod": [                    # Cluster name
          10,                      # Lambda timeout
          128                      # Lambda memory
      ]
  }

Lambda Config
~~~~~~~~~~~~~

The ``timeout``: The time (in seconds) the Lambda function is allowed to process an incoming record.

The ``memory``: The amount of memory allocated for the Lambda function execution.

Per documentation: *"All calls made to AWS Lambda must complete execution within 300 seconds. The default timeout is 3 seconds, but you can set the timeout to any value between 1 and 300 seconds."*

Processor Config
~~~~~~~~~~~~~~~~

``source_bucket``: The S3 bucket for uploading and storing the StreamAlert application code.  Open ``variables.json`` and replace the prefix with your company name.

``source_current_hash``: The checksum of the currently running Lambda function.  Used for version publishing.

``source_object_key``: The full path in S3 to the currently running Lambda function source code zip.

``handler``: The entry point to the Lambda function where events are passed into StreamAlert.

.. note:: If third-party libraries are used in rules but not specified below, they will not work.

``third_party_libraries``: Third-party Python libraries to package into the Lambda deployment package.


