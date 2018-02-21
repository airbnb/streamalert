Lambda
======

Overview
--------

StreamAlert utilizes AWS Lambda for real-time data processing and alerting.

AWS Lambda lets users to run code without needing to provision or manage servers.

A set of Lambda functions are created for each `cluster <clusters.html>`_ defined:

* Rule Processor: Analyze incoming logs against rules in real time
* Alert Processor: Deliver alerts to designated outputs

Concepts
--------
* AWS Lambda `details`_
* AWS Lambda `FAQ`_
* AWS Lambda `pricing`_

.. _details: https://docs.aws.amazon.com/lambda/latest/dg/welcome.html
.. _faq: https://aws.amazon.com/lambda/faqs/
.. _pricing: https://aws.amazon.com/lambda/pricing/


Per Cluster Lambda Settings
---------------------------

``stream_alert`` is the main configuration module which manages:

1) Lambda Functions for rule and alert processing
2) IAM roles and policies
3) SNS topic for alerts

**Template:**

.. code-block:: json
  :caption: `conf/clusters/cluster-name.json`

  {
    "stream_alert": {
      "alert_processor": {
        "timeout": 25,
        "log_level": "info",
        "memory": 128,
        "current_version": "$LATEST",
        "outputs": {
          "aws-s3": [],
          "aws-lambda": []
        }
      },
      "rule_processor": {
        "timeout": 10,
        "log_level": "debug",
        "memory": 256,
        "current_version": "$LATEST"
      }
    }
  }

**Options:**

===================  ========  ===========
Key                  Required  Description
-------------------  --------  -----------
``timeout``          ``Yes``   The time (in seconds) the Lambda function is allowed to process an incoming record. The timeout can be set to any value between 1 and 300 seconds.
``memory``           ``Yes``   The amount of memory allocated for the Lambda function execution.
``log_level``        ``No``    The log level for the Lambda function, can be either ``info`` or ``debug``. Default is ``info``, but enabling ``debug`` can help with diagnosing errors in each function.
``current_version``  ``Yes``   The most current published version of the Lambda function.
``outputs``          ``Yes``   A collection of S3 bucket IDs or AWS Lambda function names to configure as valid outputs.  By default, ``aws-s3`` should contain the bucket created by the ``stream_alert`` module: ``prefix.cluster.streamalerts``.  Optionally, if the alert processor needs to invoke other Lambda functions from within your AWS account, specify a list of function names.
===================  ========  ===========

vpc_config
~~~~~~~~~~

To enable StreamAlert's Alert Processor to access resources inside a VPC, you must provide additional VPC-specific configuration information.

`More information <http://docs.aws.amazon.com/lambda/latest/dg/vpc.html>`_

**Template:**

.. code-block:: json
  :caption: `conf/clusters/cluster-name.json`

  {
    "alert_processor": {
      "vpc_config": {
        "subnet_ids": [],
        "security_group_ids": []
      }
    }
  }

**Options:**

======================  ========  ===========
Key                     Required  Description
----------------------  --------  -----------
``subnet_ids``          ``Yes``   A list of VPC subnet IDs to run the Alert Processor in
``security_group_ids``  ``Yes``   A list of security group IDs to apply to the Alert Processor
======================  ========  ===========

inputs
~~~~~~

StreamAlert's Rule Processor can be configured to support SNS as an input data source.

**Template:**

.. code-block:: json
  :caption: `conf/clusters/cluster-name.json`

  {
    "rule_processor": {
      "inputs": {
        "aws-sns:": []
      }
    }
  }

Global Lambda Config
--------------------

The ``conf/lambda.json`` configuration file controls common settings across all Lambda functions.

**Template:**

.. code-block:: json
  :caption: `conf/lambda.json`

  {
    "alert_processor_config": {
      "handler": "stream_alert.rule_processor.main.handler",
      "source_bucket": "prefix.streamalert.source",
      "source_current_hash": "auto_generated_hash",
      "source_object_key": "auto_generated_s3_object_key",
      "third_party_libraries": [
        "jsonpath_rw",
        "netaddr"
      ]
    },
    "rule_processor_config": {
      "handler": "stream_alert.rule_processor.main.handler",
      "source_bucket": "prefix.streamalert.source",
      "source_current_hash": "auto_generated_hash",
      "source_object_key": "auto_generated_s3_object_key",
      "third_party_libraries": []
    }
  }

**Options:**

=========================    ========  ===========
Key                          Required  Description
-------------------------    --------  -----------
``source_bucket``            ``Yes``   The S3 bucket for uploading and storing the StreamAlert application code.  Open ``variables.json`` and replace the prefix with your company name.
``source_current_hash``      ``Yes``   The checksum of the currently running Lambda function.  Used for version publishing.
``source_object_key``        ``Yes``   The full path in S3 to the currently running Lambda function source code zip.
``handler``                  ``Yes``   The entry point to the Lambda function where events are passed into StreamAlert.
``third_party_libraries``    ``Yes``   Third-party Python libraries to package into the Lambda deployment package.
=========================    ========  ===========

.. note:: If third-party libraries are used in rules but not specified below, they will not work.
