Clusters
========

Background
~~~~~~~~~~

StreamAlert will deploy separate infrastructure for each ``cluster`` (or environment) you define.

What constitutes a ``cluster`` is up to you.

Example: You could define ``IT``, ``PCI`` and ``Production`` clusters.

Strategy
--------

Cluster definition is up to you.

Common patterns:

1. Define a single cluster to receive and process data from all of your environments
2. Define a cluster for each of your environments
3. Define a cluster for each organization, which may have one or more environments

Which one you choose is largely dependent on your processes, requirements and how your team organizes itself

Option \(2\) is encouraged because it provides segmentation for ingestion, analysis and storage, on a per-cluster basis, ensuring that folks only have access to the infrastructure and data they need to get their job done.

Configuration
-------------

Each cluster lives in its own ``json`` file in the ``conf/clusters`` directory.

A cluster file contains name, region, modules, and outputs.

An example ``production`` cluster:

.. code-block:: json

  {
    "id": "production",
    "region": "us-west-2",
    "modules": {
      "stream_alert": {
        "alert_processor": {
          "timeout": 25,
          "memory": 128,
          "current_version": "$LATEST"
        },
        "rule_processor": {
          "timeout": 10,
          "memory": 256,
          "current_version": "$LATEST"
        }
      },
      "cloudwatch_monitoring": {
        "enabled": true
      },
      "kinesis": {
        "streams": {
          "shards": 1,
          "retention": 24
        },
        "firehose": {
          "enabled": true,
          "s3_bucket_suffix": "streamalert.results"
        }
      },
      "kinesis_events": {
        "enabled": true
      }
    },
    "outputs": {
      "kinesis": [
        "username",
        "access_key_id",
        "secret_key"
      ]
    }
  }

Customizing Clusters
~~~~~~~~~~~~~~~~~~~~

Each StreamAlert cluster is made up of multiple modules.

Each module corresponds to a Terraform module found in the ``terraform/modules`` directory, and serves a specific purpose in a StreamAlert cluster.

After making modifications to a cluster file, make sure you apply the changes with:

.. code-block:: bash

  $ python manage.py terraform build

This will regenerate the necessary Terraform files and then apply the changes.

Module: StreamAlert
--------------------

The main module for StreamAlert.

It creates both AWS Lambda functions, aliases, an SNS topic, IAM permissions, and more.

See `Lambda Settings <lambda.html>`_ for all customization options.

Module: Kinesis
---------------

This module contains configuration for the Kinesis Streams and Kinesis Firehose infrastructure.

See `Kinesis <kinesis.html>`_ for all customization options.

Module: CloudWatch Monitoring
-----------------------------

Amazon CloudWatch is a monitoring service for AWS cloud resources.

To ensure a StreamAlert cluster is running properly, this module creates metric based alarms across all component services.  This ensures that ingesting, processing, and storage of data is operating normally.

If any of the services cross a predefined threshold, an alarm is generated.

To disable CloudWatch alarms, set to ``false``.

**Template:**

.. code-block:: json

  {
    "cloudwatch_monitoring": {
      "enabled": true
    }
  }

To configure the SNS topic used to receive CloudWatch metric alarms, use one of the following options in the ``conf/global.json`` configuration file.

Option 1: Create a new topic.  This tells the StreamAlert CLI to create a new topic called ``stream_alert_monitoring``.  All clusters will send alarms to this topic.

.. code-block:: json

  {
    "account": {
      "...": "..."
    },
    "terraform": {
      "...": "..."
    },
    "infrastructure": {
      "monitoring": {
        "create_sns_topic": true
      }
    }
  }

Option 2: Use an existing SNS topic within your AWS account (created outside of the scope of StreamAlert).

.. code-block:: json

  {
    "account": {
      "...": "..."
    },
    "terraform": {
      "...": "..."
    },
    "infrastructure": {
      "monitoring": {
        "sns_topic_name": "my_sns_topic"
      }
    }
  }

Module: Kinesis Events
----------------------

The Kinesis Events module connects a Lambda function to a Kinesis Stream.

By default, this connects the ``stream_alert`` module to the ``kinesis`` module.

To disable this mapping, set to ``false``

**Template:**

.. code-block:: json

  {
    "kinesis_events": {
      "enabled": true
    }
  }

Module: CloudTrail
------------------

`AWS CloudTrail <https://aws.amazon.com/cloudtrail/>`_ is a service that enables compliance, operational auditing, and risk auditing of your AWS account.

StreamAlert has native support for enabling and monitoring CloudTrail logs with the ``cloudtrail`` module.

When writing rules for CloudTrail data, use the ``cloudwatch:event`` log source.

By default, all API calls will be logged and accessible from rules.

**Template:**

.. code-block:: json

  {
    "cloudtrail": {
      "enabled": true
    }
  }

**Options:**

===================  ========  ==================================  ===========
Key                  Required  Default                             Description
-------------------  --------  ----------------------------------  -----------
``enabled``          ``Yes``   -                                   To enable/disable the CloudTrail.
``existing_trail``   ``No``    ``false``                           Set to ``true`` if the account has an existing CloudTrail.  This is to avoid duplication of data collected by multiple CloudTrails.
``is_global_trail``  ``No``    ``true``                            If the CloudTrail should collect events from any region.
``event_pattern``    ``No``    ``{"account": ["<accound_id>"]}``   The CloudWatch Events pattern to send to Kinesis.  `More information <http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html>`_.
===================  ========  ==================================  ===========

Module: Flow Logs
-----------------

VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your AWS VPC.

In the settings below, an arbitrary amount of subnets, vpcs, and enis can be enabled.

When writing rules for this data, use the ``cloudwatch:flow_logs`` log source.

**Template:**

.. code-block:: json

  {
    "flow_logs": {
      "enabled": true,
      "log_group_name": "<name-of-cloudwatch-log-group>",
      "subnets": [
        "subnet-id-1",
        "..."
      ],
      "vpcs": [
        "vpc-id-1",
        "..."
      ],
      "enis": [
        "eni-id-1",
        "..."
      ]
    }
  }

**Options:**

==================  ========  ====================================  ===========
Key                 Required  Default                               Description
------------------  --------  ------------------------------------  -----------
``enabled``         Yes       -                                     To enable/disable the Flow log creation.
``log_group_name``  No        prefix_cluster_streamalert_flow_logs  The name of the CloudWatch Log group.
``subnets``         No        None                                  The list of AWS VPC subnet IDs to collect flow logs from.
``vpcs``            No        None                                  The list of AWS VPC IDs to collect flow logs from.
``enis``            No        None                                  The list of AWS ENIs to collect flow logs from.
==================  ========  ====================================  ===========

Module: S3 Events
-----------------

Amazon S3 is one of the default datasources for StreamAlert.

S3 Object event notifications can be configured to send to Lambda each time an object is written.

When StreamAlert receives this notification, it fetches the object from S3 and analyzes it according to configured rules.

**Template**

.. code-block:: json

  {
    "s3_events": {
      "s3_bucket_id": "<input-bucket-id>"
    }
  }
