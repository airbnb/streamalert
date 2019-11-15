Clusters
========

Inbound data is directed to one of StreamAlert's *clusters*, each with its own data sources
and classifier function. For many applications, one cluster may be enough. However, adding
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
configuration, described below.

Changes to cluster configuration can be applied with one of the following:

.. code-block:: bash

  ./manage.py build  # Apply all changes
  ./manage.py build --target cloudwatch_monitoring_*  # Only apply changes to CloudWatch module for all clusters

Configuration options are divided into different modules, each of which is discussed below.


.. _main_cluster_module:

Classifier Function
-------------------
``stream_alert`` is the only required module because it configures the cluster's classifier.

Example: Minimal Cluster
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "minimal-cluster",
    "modules": {
      "stream_alert": {
        "classifier_config": {
          "enable_custom_metrics": true,
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
        }
      }
    },
    "region": "us-east-1"
  }

Example: Classifier with SNS Inputs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

  {
    "id": "sns-inputs",
    "modules": {
      "stream_alert": {
        "classifier_config": {
          "enable_custom_metrics": true,
          "inputs": {
            "aws-sns": [
              "arn:aws:sns:REGION:ACCOUNT:TOPIC_NAME"
            ]
          },
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
        }
      }
    },
    "region": "us-east-1"
  }

Classifier Configuration Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
==========================  ===========  ===============
**Key**                     **Default**  **Description**
--------------------------  -----------  ---------------
``enable_custom_metrics``   ``true``     Enable :ref:`custom metrics <custom_metrics>` for the cluster
``enable_threat_intel``     ``false``    Toggle threat intel integration (beta)
``inputs``                  ``{}``       SNS topics which can invoke the classifier function (see example)
``log_level``               ``"info"``   Lambda CloudWatch logging level
``memory``                  ---          Lambda function memory (MB)
``timeout``                 ---          Lambda function timeout (seconds)
==========================  ===========  ===============

.. _cloudtrail:

CloudTrail
----------
StreamAlert has native support for enabling and monitoring `AWS CloudTrail <https://aws.amazon.com/cloudtrail/>`_.

This module is implemented by `terraform/modules/tf_cloudtrail <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_cloudtrail>`_.

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
        "classifier_config": {
          "enable_custom_metrics": true,
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
        }
      }
    },
    "region": "us-east-1"
  }

This creates a new CloudTrail and an S3 bucket for the resulting logs. Each new object in the bucket
invokes the StreamAlert classifier function via :ref:`S3 events <s3_events>`. For this data, rules should
be written against the ``cloudtrail:events`` log type.

Example: CloudTrail via CloudWatch Logs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: json

    {
      "id": "cloudtrail-via-cloudwatch",
      "modules": {
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
          "classifier_config": {
            "enable_custom_metrics": true,
            "log_level": "info",
            "log_retention_days": 14,
            "memory": 128,
            "timeout": 60
          }
        }
      },
      "region": "us-east-1"
    }

This also creates the CloudTrail and S3 bucket, but now the CloudTrail logs are also delivered to
CloudWatch Logs and then to a Kinesis stream via a CloudWatch Logs Subscription Filter.
This can scale to higher throughput, since StreamAlert does not have to download potentially very
large files from S3. In this case, rules should be written against the ``cloudwatch:cloudtrail`` log type.

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

This module is implemented by `terraform/modules/tf_cloudwatch_logs_destination <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_cloudwatch_logs_destination>`_.

Example: CloudWatch Logs Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: json

  {
    "id": "cloudwatch-logs-example",
    "modules": {
      "cloudwatch_logs_destination": {
        "cross_account_ids": [
          "111111111111"
        ],
        "enabled": true,
        "regions": [
          "ap-northeast-1",
          "ap-northeast-2",
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
        "classifier_config": {
          "enable_custom_metrics": true,
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
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
to monitor the health the classifier Lambda function(s) and, if applicable, the respective Kinesis stream.

This module is implemented by `terraform/modules/tf_monitoring <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_monitoring>`_.

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
        "classifier_config": {
          "enable_custom_metrics": true,
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
        }
      }
    },
    "region": "us-east-1"
  }

This enables both the Kinesis and Lambda alarms and illustrates how the alarm thresholds can be tuned.
A total of 5 alarms will be created:

* Classifier Lambda function invocation errors
* Classifier Lambda function throttles
* Classifier Lambda function iterator age, applicable only for Kinesis invocations
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
By default, StreamAlert automatically creates a ``<prefix>_streamalert_monitoring`` SNS topic that receives
CloudWatch metric alarm notifications. If you would instead like to use an existing SNS topic for
metric alarms, edit the ``monitoring`` section of `conf/global.json <https://github.com/airbnb/streamalert/tree/stable/conf/global.json>`_
as follows:

.. code-block:: json

  {
    "infrastructure": {
      "...": "...",

      "monitoring": {
        "sns_topic_name": "existing-topic-name"
      },

      "...": "..."
    }
  }

In either case, to receive metric alarms, simply `subscribe to the SNS topic <https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html>`_.


.. _kinesis_module:

Kinesis Data Streams
--------------------

This module creates a
`Kinesis Data Stream <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_
in the cluster, which is the most common approach for StreamAlert data ingestion.
In fact, the :ref:`CloudTrail <cloudtrail>`, :ref:`CloudWatch Logs <cloudwatch_logs>`,
and :ref:`VPC Flow Logs<flow_logs>` cluster modules all rely on Kinesis streams for data delivery.

Each Kinesis stream is a set of *shards*, which in aggregate determine the total data capacity of
the stream. Indeed, this is the primary motivation for StreamAlert's cluster design - each cluster
can have its own data stream whose shard counts can be configured individually.

This module is implemented by `terraform/modules/tf_kinesis_streams <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_kinesis_streams>`_.

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
        "classifier_config": {
          "enable_custom_metrics": true,
          "log_level": "info",
          "log_retention_days": 14,
          "memory": 128,
          "timeout": 60
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
StreamAlert classifier function in this cluster. The ``outputs`` instruct Terraform to print the IAM
username and access keypair for the newly created user.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

The ``kinesis`` module expects a single key (``streams``) whose value is a dictionary with the
following options:

=======================  ==================================  ===============
**Key**                  **Default**                         **Description**
-----------------------  ----------------------------------  ---------------
``create_user``          ``false``                           Create an IAM user authorized to ``PutRecords`` on the stream
``retention``            ---                                 Length of time (hours) data records remain in the stream
``shard_level_metrics``  ``[]``                              Enable these `enhanced shard-level metrics <https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html#kinesis-metrics-shard>`_
``shards``               ---                                 Number of shards (determines stream data capacity)
``trusted_accounts``     ``[]``                              Authorize these account IDs to assume an IAM role which can write to the stream
``stream_name``          ``<prefix>_<cluster>_streamalert``  [optional] Custom name for the stream that will be created
=======================  ==================================  ===============

Scaling
~~~~~~~

If the need arises to scale a Kinesis Stream, the process below is recommended.

First, update the Kinesis Stream shard count with the following command:

.. code-block:: bash

  $ aws kinesis update-shard-count \
    --stream-name <prefix>_<cluster>_streamalert_kinesis \
    --target-shard-count <new_shard_count> \
    --scaling-type UNIFORM_SCALING

`AWS CLI reference for update-shard-count <http://docs.aws.amazon.com/cli/latest/reference/kinesis/update-shard-count.html>`_

Repeat this process for each cluster in your deployment.

Note: It can take several minutes to create the new shards.

Then, update each respective cluster configuration file with the updated shard count.

Finally, apply the Terraform changes to ensure a consistent state.

.. code-block:: bash

  $ python manage.py build --target kinesis


.. _kinesis_events:

Kinesis Events
--------------

The Kinesis Events module connects a Kinesis Stream to the classifier Lambda function.

.. note:: The :ref:`Kinesis module <kinesis_module>` must also be enabled.

This module is implemented by `terraform/modules/tf_kinesis_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_kinesis_events>`_.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

===============  ============  ===============
**Key**          **Default**   **Description**
---------------  ------------  ---------------
``batch_size``   ``100``       Max records the classifier function can receive per invocation
``enabled``      ``false``     Toggle the kinesis events on and off
===============  ============  ===============


.. _flow_logs:

VPC Flow Logs
-------------

`VPC Flow Logs <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html>`_
capture information about the IP traffic going to and from an AWS VPC.

When writing rules for this data, use the ``cloudwatch:flow_logs`` log source.

.. note:: The :ref:`Kinesis module <kinesis_module>` must also be enabled.

This module is implemented by `terraform/modules/tf_flow_logs <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_flow_logs>`_.

Example: Flow Logs Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

    {
      "id": "prod",
      "modules": {
        "flow_logs": {
          "enis": [],
          "enabled": true,
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
          "classifier_config": {
            "enable_custom_metrics": true,
            "log_level": "info",
            "log_retention_days": 14,
            "memory": 128,
            "timeout": 60
          }
        }
      },
      "region": "us-east-1"
    }

This creates the ``<prefix>_prod_streamalert_flow_logs`` CloudWatch Log Group, adds flow logs
to the specified subnet, eni, and vpc IDs with the log group as their target, and adds a CloudWatch
Logs Subscription Filter to that log group to send to Kinesis for consumption by StreamAlert.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

=====================  =============================================================================================================================================  ===============
**Key**                **Default**                                                                                                                                    **Description**
---------------------  ---------------------------------------------------------------------------------------------------------------------------------------------  ---------------
``enabled``            ---                                                                                                                                            Toggle flow log creation
``flow_log_filter``    ``[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]``   Toggle flow log creation
``log_retention``      ``7``                                                                                                                                          Day for which logs should be retained in the log group
``enis``               ``[]``                                                                                                                                         Add flow logs for these ENIs
``subnets``            ``[]``                                                                                                                                         Add flow logs for these VPC subnet IDs
``vpcs``               ``[]``                                                                                                                                         Add flow logs for these VPC IDs
=====================  =============================================================================================================================================  ===============

.. note:: One of the following **must** be set for this module to have any result: ``enis``, ``subnets``, or ``vpcs``

.. _s3_events:

S3 Events
---------

You can enable `S3 event notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
on any of your S3 buckets to invoke the StreamAlert classifier function. When the StreamAlert classifier
function receives this notification, it downloads the object from S3 and runs each record
through the classification logic.

This module is implemented by `terraform/modules/tf_s3_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_s3_events>`_.

Example: S3 Events Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

    {
      "id": "s3-events-example",
      "modules": {
        "s3_events": {
          "bucket_name_01": [
            {
              "filter_prefix": "AWSLogs/1234",
              "filter_suffix": ".log"
            },
            {
              "filter_prefix": "AWSLogs/5678"
            }
          ],
          "bucket_name_02": []
        },
        "stream_alert": {
          "classifier_config": {
            "enable_custom_metrics": true,
            "log_level": "info",
            "log_retention_days": 14,
            "memory": 128,
            "timeout": 60
          }
        }
      },
      "region": "us-east-1"
    }

This configures the two buckets (``bucket_name_01`` and ``bucket_name_02``) to notify the classifier
function in this cluster when new objects arrive in the bucket at the specified (optional) prefix(es),
provided the objects have the specified (optional) suffix(es). Additionally, this will authorize the
classifier to download objects from each bucket.

Configuration Options
~~~~~~~~~~~~~~~~~~~~~
The ``s3_events`` module expects a *dictionary/map* of bucket names, where the value for each key
(bucket name) is a list of maps. Each map in the list can include optional prefixes (``filter_prefix``)
and suffixes (``filter_suffix``) to which the notification should be applied. The mere existence of a
bucket name in this map within this module implicitly enables event notifications for said bucket.
Note that the value specified for the map of prefixes and suffixes can be an empty list (``[]``).
An empty list will enable event notifications for **all** objects created in the bucket by default.

See the above example for how prefixes/suffixes can be (optionally) specified (as in "bucket_name_01")
and how to use the empty list to enable bucket-wide notifications (as in "bucket_name_02").
