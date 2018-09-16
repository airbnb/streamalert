Clusters
========

Inbound data is directed to one of your StreamAlert *clusters*, each with its own data sources
and rule processor. For many applications, one cluster may be enough. However, adding
additional clusters can potentially improve performance and provide isolated analysis pipelines. For
example, you could have:

* A cluster dedicated to `StreamAlert apps <app-configuration.html>`_
* A separate cluster for each of your inbound `Kinesis Data Streams <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_
* A separate cluster for data from each environment (prod, staging, corp, etc)

.. note:: Alerting and historical search components are not cluster-specific,
          although alerts will indicate their originating cluster.

Each cluster is defined by its own JSON file in the
`conf/clusters <https://github.com/airbnb/streamalert/tree/stable/conf/clusters>`_ directory.
To add a new cluster, simply create a new JSON file with the cluster name and fill in your desired
configuration (described below).

Changes to cluster configuration can be applied with one of the following:

.. code-block:: bash

  ./manage.py terraform build  # Apply all changes
  ./manage.py terraform build --target cloudtrail  # Apply changes to CloudTrail module only

Configuration options are divided into different modules, each of which is discussed below.


.. _main_cluster_module:

Rule Processor
--------------
``stream_alert`` is the only required module because it configures the cluster's rule processor.

This module is implemented by `terraform/modules/tf_stream_alert <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert>`_.

Example: Minimal Cluster
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "minimal-cluster",
    "modules": {
      "stream_alert": {
        "rule_processor": {
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "region": "us-east-1"
  }

Example: Rule Processor with SNS Inputs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "sns-inputs",
    "modules": {
      "stream_alert": {
        "rule_processor": {
          "enable_metrics": true,
          "inputs": {
            "aws-sns": [
              "arn:aws:sns:REGION:ACCOUNT:TOPIC_NAME"
            ]
          },
          "log_level": "info",
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "region": "us-east-1"
  }

Configuration Options
~~~~~~~~~~~~~~~~~~~~~
=======================  ===========  ===============
**Key**                  **Default**  **Description**
-----------------------  -----------  ---------------
``enable_metrics``       ``true``     Enable :ref:`custom metrics <custom_metrics>` for the cluster
``enable_threat_intel``  ``false``    Toggle threat intel integration (beta)
``inputs``               ``{}``       SNS topics which can invoke the rule processor (see example)
``log_level``            ``"info"``   Lambda CloudWatch logging level
``memory``               ---          Lambda function memory (MB)
``timeout``              ---          Lambda function timeout (seconds)
=======================  ===========  ===============

.. _cloudtrail:

CloudTrail
----------
StreamAlert has native support for enabling and monitoring `AWS CloudTrail <https://aws.amazon.com/cloudtrail/>`_.

This module is implemented by `terraform/modules/tf_stream_alert_cloudtrail <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_cloudtrail>`_.

Example: CloudTrail via S3 Events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "cloudtrail-s3-events",
    "modules": {
      "cloudtrail": {
        "enable_kinesis": false,
        "enable_logging": true
      },
      "s3_events": [
        {
          "bucket_id": "PREFIX.CLUSTER.streamalert.cloudtrail"
        }
      ],
      "stream_alert": {
        "rule_processor": {
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "region": "us-east-1"
  }

This creates a new CloudTrail and an S3 bucket for the resulting logs. Each new object in the bucket
invokes the StreamAlert rule processor via :ref:`S3 events <s3_events>`. For this data, rules should
be written against the ``cloudtrail:events`` log type.

Example: CloudTrail via CloudWatch Logs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: json

    {
      "id": "cloudtrail-via-cloudwatch",
      "modules": {
        "cloudwatch": {
          "enabled": true
        },
        "cloudtrail": {
          "enable_kinesis": true,
          "enable_logging": true,
          "send_to_cloudwatch": true
        },
        "kinesis": {
          "streams": {
            "retention": 96,
            "shards": 10
          }
        },
        "kinesis_events": {
          "batch_size": 10,
          "enabled": true
        },
        "stream_alert": {
          "rule_processor": {
            "memory": 128,
            "timeout": 10
          }
        }
      },
      "region": "us-east-1"
    }

This also creates the CloudTrail and S3 bucket, but now the CloudTrail logs are also delivered to
CloudWatch Logs and then to a Kinesis subscription which feeds the rule processor. This can scale to
higher throughput, since StreamAlert does not have to download potentially very large files from
S3. In this case, rules should be written against the ``cloudwatch:events`` log type.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~
==============================  =================================  ===============
**Key**                         **Default**                        **Description**
------------------------------  ---------------------------------  ---------------
``cloudwatch_destination_arn``  (Computed from CloudWatch module)  CloudWatch subscription filter destination ARN
``cross_account_ids``           ``[]``                             Grant write access to the CloudTrail S3 bucket for these account IDs
``enable_kinesis``              ``true``                           Toggle Kinesis subscription to CloudWatch logs
``enable_logging``              ``true``                           Toggle CloudTrail logging
``event_pattern``               ``{"account": ["<accound_id>"]}``  The `CloudWatch Events pattern <http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html>`_ to send to Kinesis
``exclude_home_region_events``  ``false``                          Ignore events from the StreamAlert deployment region
``existing_trail``              ``false``                          If ``true``, a new CloudTrail will *not* be created
``is_global_trail``             ``true``                           If ``true``, the CloudTrail is applied to all regions
``send_to_cloudwatch``          ``false``                          Toggle CloudTrail delivery to CloudWatch Logs
==============================  =================================  ===============


.. _cloudwatch_logs:

CloudWatch Logs
---------------
StreamAlert makes it easy to ingest
`CloudWatch Logs <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html>`_
from any AWS account. A common use case is to ingest and scan CloudTrail from multiple AWS accounts
(delivered via CloudWatch Logs), but you could also ingest any application logs delivered to CloudWatch.

.. note:: The :ref:`Kinesis module <kinesis_module>` must also be enabled.

This module is implemented by `terraform/modules/tf_stream_alert_cloudwatch <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_cloudwatch>`_.

Example: CloudWatch Logs Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: json

  {
    "id": "cloudwatch-logs-example",
    "modules": {
      "cloudwatch": {
        "cross_account_ids": [
          "111111111111"
        ],
        "enabled": true,
        "excluded_regions": [
          "ap-northeast-1",
          "ap-northeast-2",
          "ap-south-1",
          "ap-southeast-1",
          "ap-southeast-2"
        ]
      },
      "kinesis": {
        "streams": {
          "retention": 96,
          "shards": 10
        }
      },
      "kinesis_events": {
        "batch_size": 100,
        "enabled": true
      },
      "stream_alert": {
        "rule_processor": {
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "region": "us-east-1"
  }

This creates an IAM role for CloudWatch subscriptions, authorized to gather logs from the StreamAlert account
as well as account 111111111111, in all regions except Asia-Pacific.

Once you have applied this change to enable StreamAlert to subscribe to CloudWatch logs, you need to
`create a subscription filter <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateSubscriptionFilter.html>`_
in the *producer* account to actually deliver the logs, optionally with
`Terraform <https://www.terraform.io/docs/providers/aws/r/cloudwatch_log_subscription_filter.html>`_.
The CloudWatch logs destination ARN will be
``arn:aws:logs:REGION:STREAMALERT_ACCOUNT:destination:stream_alert_CLUSTER_cloudwatch_to_kinesis``.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~
=====================  ===========  ===============
**Key**                **Default**  **Description**
---------------------  -----------  ---------------
``cross_account_ids``  ``[]``       Authorize StreamAlert to gather logs from these accounts
``enabled``            ``true``     Toggle the CloudWatch Logs module
``excluded_regions``   ``[]``       Do not create CloudWatch Log destinations in these regions
=====================  ===========  ===============


.. _cloudwatch_monitoring:

CloudWatch Monitoring
---------------------
To ensure data collection is running smoothly, we recommend enabling
`CloudWatch metric alarms <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#CloudWatchAlarms>`_
to monitor the health of your rule processor Lambda function and (if applicable) your Kinesis stream.

This module is implemented by `terraform/modules/tf_stream_alert_monitoring <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_monitoring>`_.

Example: Enable CloudWatch Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "cloudwatch-monitoring-example",
    "modules": {
      "cloudwatch_monitoring": {
        "enabled": true,
        "kinesis_alarms_enabled": true,
        "lambda_alarms_enabled": true,
        "settings": {
          "lambda_invocation_error_threshold": 0,
          "lambda_throttle_error_threshold": 0,
          "kinesis_iterator_age_error_threshold": 1000000,
          "kinesis_write_throughput_exceeded_threshold": 10
        }
      },
      "stream_alert": {
        "rule_processor": {
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "region": "us-east-1"
  }

This enables both the Kinesis and Lambda alarms and illustrates how the alarm thresholds can be tuned.
A total of 5 alarms will be created:

* Rule processor Lambda invocation errors
* Rule processor Lambda throttles
* Rule processor Lambda iterator age (applicable only for Kinesis invocations)
* Kinesis iterator age
* Kinesis write exceeded

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

==========================  ===========  ===============
**Key**                     **Default**  **Description**
--------------------------  -----------  ---------------
``enabled``                 ``false``    Toggle the CloudWatch Monitoring module
``kinesis_alarms_enabled``  ``true``     Toggle the Kinesis-specific metric alarms
``lambda_alarms_enabled``   ``true``     Toggle the Lambda-specific metric alarms
``settings``                ``{}``       Alarm-specific settings (see below)
==========================  ===========  ===============

There are `three settings <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html>`_ for a CloudWatch alarm:

* **Period** is the length of time to evaluate the metric
* **Evaluation Periods** is the number of periods over which to evaluate the metric
* **Threshold** is the upper or lower bound after which the alarm will trigger

The following options are available in the ``settings`` dictionary:

========================================================  ===========
**Key**                                                   **Default**
--------------------------------------------------------  -----------
``lambda_invocation_error_threshold``                     ``0``
``lambda_invocation_error_evaluation_periods``            ``1``
``lambda_invocation_error_period``                        ``300``
``lambda_throttle_error_threshold``                       ``0``
``lambda_throttle_error_evaluation_periods``              ``1``
``lambda_throttle_error_period``                          ``300``
``lambda_iterator_age_error_threshold``                   ``1000000``
``lambda_iterator_age_error_evaluation_periods``          ``1``
``lambda_iterator_age_error_period``                      ``300``
``kinesis_iterator_age_error_threshold``                  ``1000000``
``kinesis_iterator_age_error_evaluation_periods``         ``1``
``kinesis_iterator_age_error_period``                     ``300``
``kinesis_write_throughput_exceeded_threshold``           ``10``
``kinesis_write_throughput_exceeded_evaluation_periods``  ``6``
``kinesis_write_throughput_exceeded_period``              ``300``
========================================================  ===========

Receiving CloudWatch Metric Alarms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
By default, StreamAlert automatically creates a ``stream_alert_monitoring`` SNS topic that receives
CloudWatch metric alarm notifications. If you would instead like to use an existing SNS topic for
metric alarms, edit the ``monitoring`` section of `conf/global.json <https://github.com/airbnb/streamalert/tree/stable/conf/global.json>`_
as follows:

.. code-block:: json

  {
    "infrastructure": {
      "...": "...",

      "monitoring": {
        "sns_topic_name": "your-existing-topic-name"
      },

      "...": "..."
    }

In either case, to receive metric alarms, simply `subscribe to the SNS topic <https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html>`_.


.. _kinesis_module:

Kinesis Data Streams
--------------------

This module creates a
`Kinesis Data Stream <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_
in your cluster, which is the most common approach for StreamAlert data ingestion.
In fact, the :ref:`CloudTrail <cloudtrail>`, :ref:`CloudWatch Logs <cloudwatch_logs>`,
and :ref:`VPC Flow Logs<flow_logs>` cluster modules all rely on Kinesis streams for data delivery.

Each Kinesis stream is a set of *shards*, which in aggregate determine the total data capacity of
your stream. Indeed, this is the primary motivation for StreamAlert's cluster design - each cluster
can have its own data stream whose shard counts can be configured individually.

This module is implemented by `terraform/modules/tf_stream_alert_kinesis_streams <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_kinesis_streams>`_.

Example: Kinesis Cluster
~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: json

  {
    "id": "kinesis-example",
    "modules": {
      "kinesis": {
        "streams": {
          "create_user": true,
          "retention": 24,
          "shard_level_metrics": [
            "IncomingBytes",
            "IncomingRecords",
            "IteratorAgeMilliseconds",
            "OutgoingBytes",
            "OutgoingRecords",
            "WriteProvisionedThroughputExceeded"
          ],
          "shards": 1
        }
      },
      "kinesis_events": {
        "batch_size": 100,
        "enabled": true
      },
      "stream_alert": {
        "rule_processor": {
          "memory": 128,
          "timeout": 10
        }
      }
    },
    "outputs": {
      "kinesis": [
        "username",
        "access_key_id",
        "secret_key"
      ]
    },
    "region": "us-east-1",
  }

This creates a Kinesis stream and an associated IAM user and hooks up stream events to the
StreamAlert rule processor in this cluster. The ``outputs`` instruct Terraform to print the IAM
username and access keypair for the newly created user.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

The ``kinesis`` module expects a single key (``streams``) whose value is a dictionary with the
following options:

=======================  ============  ===============
**Key**                  **Default**   **Description**
-----------------------  ------------  ---------------
``create_user``          ``false``     Create an IAM user authorized to ``PutRecords`` on the stream
``retention``            ---           Length of time (hours) data records remain in the stream
``shard_level_metrics``  ``[]``        Enable these `enhanced shard-level metrics <https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html#kinesis-metrics-shard>`_
``shards``               ---           Number of shards (determines stream data capacity)
``trusted_accounts``     ``[]``        Authorize these account IDs to assume an IAM role which can write to the stream
=======================  ============  ===============

Scaling
~~~~~~~

If the need arises to scale a Kinesis Stream, the process below is recommended.

First, update the Kinesis Stream shard count with the following command:

.. code-block:: bash

  $ aws kinesis update-shard-count \
    --stream-name <prefix>_<cluster>_stream_alert_kinesis \
    --target-shard-count <new_shard_count> \
    --scaling-type UNIFORM_SCALING

`AWS CLI reference for update-shard-count <http://docs.aws.amazon.com/cli/latest/reference/kinesis/update-shard-count.html>`_

Repeat this process for each cluster in your deployment.

Note: It can take several minutes to create the new shards.

Then, update each respective cluster configuration file with the updated shard count.

Finally, Run Terraform to ensure a consistent state.

.. code-block:: bash

  $ python manage.py terraform build --target kinesis


.. _kinesis_events:

Kinesis Events
--------------

The Kinesis Events module connects a Kinesis Stream to the rule processor Lambda function.

.. note:: The :ref:`Kinesis module <kinesis_module>` must also be enabled.

This module is implemented by `terraform/modules/tf_stream_alert_kinesis_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_kinesis_events>`_.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

===============  ============  ===============
**Key**          **Default**   **Description**
---------------  ------------  ---------------
``batch_size``   ``100``       Max records the rule processor can receive per invocation
``enabled``      ``false``     Toggle the kinesis events on and off
===============  ============  ===============


.. _flow_logs:

VPC Flow Logs
-------------

`VPC Flow Logs <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html>`_
capture information about the IP traffic going to and from your AWS VPC.

When writing rules for this data, use the ``cloudwatch:flow_logs`` log source.

.. note:: The :ref:`Kinesis module <kinesis_module>` must also be enabled.

This module is implemented by `terraform/modules/tf_stream_alert_flow_logs <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_flow_logs>`_.

Example: Flow Logs Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

    {
      "id": "prod",
      "modules": {
        "flow_logs": {
          "cross_account_ids": [
            "111111111111"
          ],
          "enis": [],
          "enabled": true,
          "log_group_name": "flow-logs-test",
          "subnets": [
            "subnet-12345678"
          ],
          "vpcs": [
            "vpc-ed123456"
          ]
        },
        "kinesis": {
          "streams": {
            "retention": 24,
            "shards": 10
          }
        },
        "kinesis_events": {
          "batch_size": 2,
          "enabled": true
        },
        "stream_alert": {
          "rule_processor": {
            "memory": 128,
            "timeout": 10
          }
        }
      },
      "region": "us-east-1"
    }

This creates the ``flow-logs-test`` CloudWatch Log group, adds flow logs to the specified subnet
and vpc IDs with the log group as their target, and adds a Kinesis subscription to that log group
for StreamAlert consumption.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

=====================  ==========================================  ===============
**Key**                **Default**                                 **Description**
---------------------  ------------------------------------------  ---------------
``cross_account_ids``  ``[]``                                      Authorize flow log delivery from these accounts
``enabled``            ---                                         Toggle flow log creation
``enis``               ``[]``                                      Add flow logs for these ENIs
``log_group_name``     ``"PREFIX_CLUSTER_streamalert_flow_logs"``  Flow logs are directed to this log group
``subnets``            ``[]``                                      Add flow logs for these VPC subnet IDs
``vpcs``               ``[]``                                      Add flow logs for these VPC IDs
=====================  ==========================================  ===============


.. _s3_events:

S3 Events
---------

You can enable `S3 event notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
on any of your S3 buckets to invoke the StreamAlert rule processor. When the StreamAlert rule
processor receives this notification, it downloads the object from S3 and runs each record
through the rules engine.

This module is implemented by `terraform/modules/tf_stream_alert_s3_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_stream_alert_s3_events>`_.

Example: S3 Events Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

    {
      "id": "s3-events-example",
      "modules": {
        "s3_events": [
          {
            "bucket_id": "your-bucket-1",
            "enable_events": true
          },
          {
            "bucket_id": "your-bucket-2",
            "enable_events": true
          }
        ],
        "stream_alert": {
          "rule_processor": {
            "memory": 128,
            "timeout": 10
          }
        }
      },
      "region": "us-east-1"
    }

This configures 2 buckets to notify the rule processor in this cluster, and authorizes StreamAlert
to download objects from either bucket.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~
Unlike the other modules, ``s3_events`` expects a *list* of dictionaries. Each element represents a
single bucket source and has the following options:

==================  ===========  ===============
**Key**             **Default**  **Description**
------------------  -----------  ---------------
``bucket_id``       ---          The name of the S3 bucket
``enable_events``   ``true``     Toggle the S3 event notification
==================  ===========  ===============
