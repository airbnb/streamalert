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

An example ``production`` cluster::

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

Each cluster can be broken up into multiple modules to make up a StreamAlert cluster.

Each module corresponds to a Terraform module found in the ``terraform/modules`` directory, and serves a specific purpose in a StreamAlert cluster.

After making modifications to a cluster's file, make sure you apply it with::

  $ python stream_alert_cli.py terraform build
  
This will regenerate the necessary Terraform files and then apply the changes.

Module: StreamAlert
--------------------

See `Lambda Settings <lambda.html>`_ for customization options.

Module: Kinesis
---------------

See `Kinesis <kinesis.html>`_ for customization options.

Module: CloudWatch Monitoring
-----------------------------

Amazon CloudWatch is a monitoring service for AWS cloud resources.

To ensure a StreamAlert cluster is running properly, this module creates metric based alarms across all component services.  This ensures that ingesting, processing, and storage of data is operating normally.

If any of the services cross a predefined threshold, an alarm is generated.

To disable CloudWatch alarms, set to ``false``.

Template::

  "cloudwatch_monitoring": {
    "enabled": true
  }

Module: Kinesis Events
----------------------

The Kinesis Events module connects a Lambda function to a Kinesis Stream.

By default, this connects the ``stream_alert`` module to the ``kinesis`` module.

To disable this mapping, set to ``false``

Template::

  "kinesis_events": {
    "enabled": true
  }

Module: CloudTrail
------------------

AWS CloudTrail is a service that enables compliance, operational auditing, and risk auditing of your AWS account.

StreamAlert has native support for enabling and monitoring CloudTrail logs with the ``cloudtrail`` module.

When writing rules for CloudTrail data, use the ``cloudwatch:event`` log source.

By default, all API calls will be logged and accessible from rules.

Template::

  "cloudtrail": {
    "enabled": true
  }

Module: Flow Logs
-----------------

VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your AWS VPC.

In the settings below, an arbitrary amount of subnets, vpcs, and enis can be enabled.

When writing rules for this data, use the ``cloudwatch:flow_logs`` log source.

Template::

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
