################
Cluster Settings
################

Inbound data is directed to one of StreamAlert's *clusters*, each with its own data sources
and classifier function. For many applications, one cluster may be enough. However, adding
additional clusters can potentially improve performance. For example, you could have:

  * A cluster dedicated to `StreamAlert apps <apps.html>`_
  * A separate cluster for each of your inbound `Kinesis Data Streams <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_
  * A separate cluster for data from each environment (prod, staging, corp, etc)

.. note::

  Alerting and historical search components are global and not tied to a specific cluster,
  although alerts will indicate their originating cluster.

Each cluster is defined by its own JSON file in the
`conf/clusters <https://github.com/airbnb/streamalert/tree/stable/conf/clusters>`_ directory.
To add a new cluster, simply create a new JSON file with the cluster name and fill in your desired
configuration, described below.

Changes to cluster configuration can be applied with one of the following:

.. code-block:: bash

  python manage.py build  # Apply all changes
  python manage.py build --target cloudwatch_monitoring_*  # Only apply changes to CloudWatch Monitoring module for all clusters

*****************
Required Settings
*****************
There are a few top-level settings that are required within each cluster configuration file.
Notably, these settings configure the ``data_sources`` and ``classifier_config``.


Datasource Configuration
========================
A cluster's classifier function knows what types of data it should parse based on defined
``data_sources`` within each cluster configuration file in the ``conf/clusters`` directory.

For background on supported data source types, read `Datasources <datasources.html>`_.

.. note::

  As of release 3.0.0 data source configuration has moved from sources.json
  into the ``data_sources`` top level key for each your clusters.

Each data source (``kinesis``, ``s3``, or ``sns``) contains a mapping of specific resource names
(Kinesis stream names, S3 bucket names, etc) along with a list of log types that should be expected
from that source.

.. note::

  Log schemas are defined in one or more files in the ``conf/schemas`` directory. See
  the `Schemas <config-schemas.html>`_ page for more information, or the
  `Example Schemas <conf-schemas-examples.html>`_ page for some sample log definitions.

Each log in the list of logs instructs StreamAlert's classifier function to attempt
to parse incoming data from the given resource as that log type. The classifier will only try
to parse incoming data as types that are defined for each resource. If new types of data are
fed into one of the sources defined here, but this configuration is not updated, it will
result in failed parses in the classifier function.


Example
-------
.. code-block:: json

  {
    "data_sources": {
      "kinesis": {
        "abc_corporate_streamalert": [
          "cloudwatch",
          "cloudtrail"
        ],
        "abc_production_stream_streamalert": [
          "osquery"
        ]
      },
      "s3": {
        "abc.ghe.logs": [
          "ghe"
        ],
        "abc.hids.logs": [
          "carbonblack"
        ]
      },
      "sns": {
        "abc_sns_topic": [
          "fleet"
        ]
      }
    }
  }

.. important::

  Any data source log type that is listed must have an associated log definition
  within your `schemas <config-schemas.html>`_ definitions.


Classifier Configuration
========================
A cluster's classifier function is a required component and configurable with a few settings that
may be tweaked to help with performance or cost. These exist as part of the ``classifier_config``
block within each cluster configuration file in the ``conf/clusters`` directory.


Example: Basic Cluster
----------------------
.. code-block:: json

  {
    "id": "minimal-cluster",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_corporate_streamalert": [
          "cloudwatch"
        ]
      }
    }
  }


Example: Classifier with SNS Inputs
-----------------------------------
.. code-block:: json

  {
    "id": "sns-inputs",
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
    },
    "data_sources": {
      "sns": {
        "TOPIC_NAME": [
          "cloudwatch"
        ]
      }
    }
  }


Options
-------
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


*******
Modules
*******
Optional configuration settings are divided into different modules, which should be defined within
the ``modules`` section of each cluster configuration file in the ``conf/clusters`` directory.


.. _cloudtrail:

CloudTrail
==========
StreamAlert has native support for enabling and monitoring `AWS CloudTrail <https://aws.amazon.com/cloudtrail/>`_.

This module is implemented by `terraform/modules/tf_cloudtrail <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_cloudtrail>`_.


Example: CloudTrail via S3 Events
---------------------------------
.. code-block:: json

  {
    "id": "cloudtrail-s3-events",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "s3": {
        "abc-prod-streamalert-cloudtrail": [
          "cloudtrail"
        ]
      }
    },
    "modules": {
      "cloudtrail": {
        "s3_settings": {
          "enable_events": true
        }
      }
    }
  }

This creates a new CloudTrail and an S3 bucket for the resulting logs. Each new object in the bucket
will invoke the StreamAlert classifier function via S3 events. For this data, rules should be written
against the ``cloudtrail:events`` log type.


Example: CloudTrail via CloudWatch Logs
---------------------------------------
.. code-block:: json

  {
    "id": "cloudtrail-via-cloudwatch",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_prod_streamalert": [
          "cloudwatch"
        ]
      }
    },
    "modules": {
      "cloudtrail": {
        "s3_settings": {
          "enable_events": true
        },
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
      }
    }
  }

This also creates the CloudTrail and S3 bucket, but now the CloudTrail logs are also delivered to
CloudWatch Logs Group that forwards them to a Kinesis stream via a CloudWatch Logs Subscription Filter.
This can scale to higher throughput, since StreamAlert does not have to download potentially very
large files from S3. In this case, rules should be written against the ``cloudwatch:cloudtrail`` log type.


Options
-------
==============================  ===================================================  ===============
**Key**                         **Default**                                          **Description**
------------------------------  ---------------------------------------------------  ---------------
``enabled``                     ``true``                                             Toggle the ``cloudtrail`` module
``enable_logging``              ``true``                                             Toggle to ``false`` to pause logging to the CloudTrail
``exclude_home_region_events``  ``false``                                            Ignore events from the StreamAlert deployment region. This only has an effect if ``send_to_cloudwatch`` is set to ``true``
``is_global_trail``             ``true``                                             If ``true``, the CloudTrail is applied to all regions
``send_to_cloudwatch``          ``false``                                            Enable CloudTrail delivery to CloudWatch Logs. Logs sent to CloudWatch Logs are forwarded to this cluster's Kinesis stream for processing. If this is enabled, the ``enable_s3_events`` option should be disabled to avoid duplicative processing.
``cloudwatch_destination_arn``  (Computed from CloudWatch Logs Destination module)   CloudWatch Destination ARN used for forwarding data to this cluster's Kinesis stream. This has a default value but can be overridden here with a different CloudWatch Logs Destination ARN
``send_to_sns``                 ``false``                                            Create an SNS topic to which notifications should be sent when CloudTrail puts a new object in the S3 bucket. The topic name will be the same as the S3 bucket name
``allow_cross_account_sns``     ``false``                                            Allow account IDs specified in the ``cross_account_ids`` array within the ``s3_settings`` (see below) to also send SNS notifications to the created SNS Topic
``s3_settings``                 ``None``                                             Configuration options for CloudTrail related to S3. See the `S3 Options`_ section below for details.
==============================  ===================================================  ===============

S3 Options
----------
The ``cloudtrail`` module has a subsection of ``s3_settings``, which contains options related to S3.

========================  ===================================================  ===============
**Key**                   **Default**                                          **Description**
------------------------  ---------------------------------------------------  ---------------
``cross_account_ids``     ``[]``                                               Grant write access to the CloudTrail S3 bucket for these account IDs. The primary, aka deployment account ID, will be added to this list.
``enable_events``         ``false``                                            Enable S3 events for the logs sent to the S3 bucket. These will invoke this cluster's classifier for every new object in the CloudTrail S3 bucket
``ignore_digest``         ``true``                                             If ``enable_events`` is enabled, setting ``ignore_digest`` to ``false`` will also process S3 files that are created within the ``AWSLogs/<account-id>/CloudTrail-Digest``. Defaults to ``true``.
``bucket_name``           ``prefix-cluster-streamalert-cloudtrail``            Name of the S3 bucket to be used for the CloudTrail logs. This can be overridden, but defaults to ``prefix-cluster-streamalert-cloudtrail``
``event_selector_type``   ``""``                                               An S3 event selector to enable object level logging for the account's S3 buckets. Choices are: "ReadOnly", "WriteOnly", "All", or "", where "" disables object level logging for S3
========================  ===================================================  ===============

.. _cloudwatch_events:

CloudWatch Events
=================
StreamAlert supports ingestion of events published to CloudWatch Events for processing.

This module is implemented by `terraform/modules/tf_cloudwatch_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_cloudwatch_events>`_.

.. note:: The :ref:`Kinesis module <kinesis>` must also be enabled.


Example
-------
.. code-block:: json

  {
    "id": "cloudwatch-events-example",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_prod_streamalert": [
          "cloudwatch"
        ]
      }
    },
    "modules": {
      "cloudwatch_events": {
        "event_pattern": {
          "account": [
            "123456789012"
          ],
          "detail-type": [
            "EC2 Instance Launch Successful",
            "EC2 Instance Launch Unsuccessful",
            "EC2 Instance Terminate Successful",
            "EC2 Instance Terminate Unsuccessful"
          ]
        },
        "cross_account": {
          "accounts": {
            "123456789012": [
              "us-east-1"
            ]
          },
          "organizations": {
            "o-aabbccddee": [
              "us-east-1"
            ]
          }
        }
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
      }
    }
  }

This creates a CloudWatch Events Rule that will publish all events that match the provided
``event_pattern`` to the Kinesis Stream for this cluster. Note in the example above that a custom
``event_pattern`` is supplied, but may be omitted entirely. To override the default ``event_patten``
(shown below), a value of ``None`` or ``{}`` may also be supplied to capture all events,
regardless of which account the logs came from. In this case, rules should be written against
the ``cloudwatch:events`` log type.


Options
-------
=====================  ===================================  ===============
**Key**                **Default**                          **Description**
---------------------  -----------------------------------  ---------------
``event_pattern``      ``{"account": ["<account-id>"]}``    The `CloudWatch Events pattern <http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html>`_ to control what is sent to Kinesis
``cross_account``      ``None``                             Configuration options to enable cross account access for specific AWS Accounts and Organizations. See the `Cross Account Options`_ section below for details.
=====================  ===================================  ===============

Cross Account Options
---------------------
The ``cross_account`` section of the ``cloudwatch_events`` module has two subsections, outlined here. Usage of these is also shown in the example above.

=====================  ===========  ===============
**Key**                **Default**  **Description**
---------------------  -----------  ---------------
``accounts``           ``None``     A mapping of *account IDs* and regions for which cross account access should be enabled. Example: ``{"123456789012": ["us-east-1"], "234567890123": ["us-west-2"]}``
``organizations``      ``None``     A mapping of *organization IDs* and regions for which cross account access should be enabled. Example: ``{"o-aabbccddee": ["us-west-2"]}``
=====================  ===========  ===============


.. _cloudwatch_logs:

CloudWatch Logs
===============
StreamAlert makes it easy to ingest
`CloudWatch Logs <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html>`_
from any AWS account. A common use case is to ingest and scan CloudTrail from multiple AWS accounts
(delivered via CloudWatch Logs), but you could also ingest any application logs delivered to CloudWatch.

.. note:: The :ref:`Kinesis module <kinesis>` must also be enabled.

This module is implemented by `terraform/modules/tf_cloudwatch_logs_destination <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_cloudwatch_logs_destination>`_.


Example
-------
.. code-block:: json

  {
    "id": "cloudwatch-logs-example",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_prod_streamalert": [
          "cloudwatch"
        ]
      }
    },
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
      }
    }
  }

This creates an IAM role for CloudWatch subscriptions, authorized to gather logs from the StreamAlert account
as well as account 111111111111, in all regions except Asia-Pacific.

Once you have applied this change to enable StreamAlert to subscribe to CloudWatch logs, you need to
`create a subscription filter <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateSubscriptionFilter.html>`_
in the *producer* account to actually deliver the logs, optionally with
`Terraform <https://www.terraform.io/docs/providers/aws/r/cloudwatch_log_subscription_filter.html>`_.
The CloudWatch logs destination ARN will be
``arn:aws:logs:REGION:STREAMALERT_ACCOUNT:destination:streamalert_CLUSTER_cloudwatch_to_kinesis``.


Options
-------
=====================  ===========  ===============
**Key**                **Default**  **Description**
---------------------  -----------  ---------------
``enabled``            ``true``     Toggle the ``cloudwatch_logs_destination`` module
``cross_account_ids``  ``[]``       Authorize StreamAlert to gather logs from these accounts
``excluded_regions``   ``[]``       Do not create CloudWatch Log destinations in these regions
=====================  ===========  ===============


CloudWatch Monitoring
=====================
To ensure data collection is running smoothly, we recommend enabling
`CloudWatch metric alarms <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#CloudWatchAlarms>`_
to monitor the health the classifier Lambda function(s) and, if applicable, the respective Kinesis stream.

This module is implemented by `terraform/modules/tf_monitoring <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_monitoring>`_.


Example
-------
.. code-block:: json

  {
    "id": "cloudwatch-monitoring-example",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_prod_streamalert": [
          "cloudwatch"
        ]
      }
    },
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
      }
    }
  }

This enables both the Kinesis and Lambda alarms and illustrates how the alarm thresholds can be tuned.
A total of 5 alarms will be created:

* Classifier Lambda function invocation errors
* Classifier Lambda function throttles
* Classifier Lambda function iterator age, applicable only for Kinesis invocations
* Kinesis iterator age
* Kinesis write exceeded


Options
-------
==========================  ===========  ===============
**Key**                     **Default**  **Description**
--------------------------  -----------  ---------------
``enabled``                 ``false``    Toggle the ``cloudwatch_monitoring`` module
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
----------------------------------
By default, StreamAlert automatically creates a ``<prefix>_streamalert_monitoring`` SNS topic that receives
CloudWatch metric alarm notifications. If you would instead like to use an existing SNS topic for
metric alarms, see the Monitoring configuration settings for how
to set this up.

In either case, to receive notifications for metric alarms,
simply `subscribe to the SNS topic <https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html>`_.


.. _kinesis:

Kinesis (Data Streams)
======================
This module creates a
`Kinesis Data Stream <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_
in the cluster, which is the most common approach for StreamAlert data ingestion.
In fact, the :ref:`CloudTrail <cloudtrail>`, :ref:`CloudWatch Logs <cloudwatch_logs>`,
and :ref:`VPC Flow Logs<flow_logs>` cluster modules all rely on Kinesis streams for data delivery.

Each Kinesis stream is a set of *shards*, which in aggregate determine the total data capacity of
the stream. Indeed, this is the primary motivation for StreamAlert's cluster design - each cluster
can have its own data stream whose shard counts can be configured individually.

This module is implemented by `terraform/modules/tf_kinesis_streams <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_kinesis_streams>`_.


Example
-------
.. code-block:: json

  {
    "id": "kinesis-example",
    "classifier_config": {
      "enable_custom_metrics": true,
      "log_level": "info",
      "log_retention_days": 14,
      "memory": 128,
      "timeout": 60
    },
    "data_sources": {
      "kinesis": {
        "abc_prod_streamalert": [
          "cloudwatch"
        ]
      }
    },
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
          "shards": 1,
          "terraform_outputs": [
            "user_arn",
            "access_key_id",
            "secret_key"
          ]
        }
      },
      "kinesis_events": {
        "batch_size": 100,
        "enabled": true
      }
    }
  }

This creates a Kinesis stream and an associated IAM user and hooks up stream events to the
StreamAlert classifier function in this cluster. The ``terraform_outputs`` section instructs
Terraform to print the IAM User's ARN, along with the access key ID and secret key
for the newly created user.


Options
-------
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


Kinesis Scaling
---------------
If the need arises to scale a Kinesis Stream, the process below is recommended.

First, update the Kinesis Stream shard count with the following command:

.. code-block:: bash

  aws kinesis update-shard-count \
    --stream-name <prefix>_<cluster>_streamalert_kinesis \
    --target-shard-count <new_shard_count> \
    --scaling-type UNIFORM_SCALING

`AWS CLI reference for update-shard-count <http://docs.aws.amazon.com/cli/latest/reference/kinesis/update-shard-count.html>`_

Repeat this process for each cluster in your deployment.

.. note::

	It may take several minutes, or longer, for new shards to be created.

Then, update each respective cluster configuration file with the updated shard count.

Finally, apply the Terraform changes to ensure a consistent state.

.. code-block:: bash

  python manage.py build --target kinesis


Kinesis Events
==============
The Kinesis Events module connects a Kinesis Stream to the classifier Lambda function.

.. note:: The :ref:`Kinesis module <kinesis>` must also be enabled.

This module is implemented by `terraform/modules/tf_kinesis_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_kinesis_events>`_.


Options
-------
===============  ============  ===============
**Key**          **Default**   **Description**
---------------  ------------  ---------------
``batch_size``   ``100``       Max records the classifier function can receive per invocation
``enabled``      ``false``     Toggle the kinesis events on and off
===============  ============  ===============


.. _flow_logs:

VPC Flow Logs
=============
`VPC Flow Logs <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html>`_
capture information about the IP traffic going to and from an AWS VPC.

When writing rules for this data, use the ``cloudwatch:flow_logs`` log source.

.. note:: The :ref:`Kinesis module <kinesis>` must also be enabled.

This module is implemented by `terraform/modules/tf_flow_logs <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_flow_logs>`_.


Example
-------
.. code-block:: json

    {
      "id": "prod",
      "classifier_config": {
        "enable_custom_metrics": true,
        "log_level": "info",
        "log_retention_days": 14,
        "memory": 128,
        "timeout": 60
      },
      "data_sources": {
        "kinesis": {
          "abc_prod_streamalert": [
            "cloudwatch:flow_logs"
          ]
        }
      },
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
        }
      }
    }

This creates the ``<prefix>_prod_streamalert_flow_logs`` CloudWatch Log Group, adds flow logs
to the specified subnet, eni, and vpc IDs with the log group as their target, and adds a CloudWatch
Logs Subscription Filter to that log group to send to Kinesis for consumption by StreamAlert.


Options
-------
=====================  =============================================================================================================================================  ===============
**Key**                **Default**                                                                                                                                    **Description**
---------------------  ---------------------------------------------------------------------------------------------------------------------------------------------  ---------------
``enabled``            ``true``                                                                                                                                       Toggle the ``flow_logs`` module
``flow_log_filter``    ``[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]``   Toggle flow log creation
``log_retention``      ``7``                                                                                                                                          Day for which logs should be retained in the log group
``enis``               ``[]``                                                                                                                                         Add flow logs for these ENIs
``subnets``            ``[]``                                                                                                                                         Add flow logs for these VPC subnet IDs
``vpcs``               ``[]``                                                                                                                                         Add flow logs for these VPC IDs
=====================  =============================================================================================================================================  ===============

.. note:: One of the following **must** be set for this module to have any result: ``enis``, ``subnets``, or ``vpcs``


.. _s3_events:

S3 Events
=========
You can enable `S3 event notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
on any of your S3 buckets to invoke the StreamAlert classifier function. When the StreamAlert classifier
function receives this notification, it downloads the object from S3 and runs each record
through the classification logic.

This module is implemented by `terraform/modules/tf_s3_events <https://github.com/airbnb/streamalert/tree/stable/terraform/modules/tf_s3_events>`_.

Example
-------
.. _s3_event_example:

.. code-block:: json

    {
      "id": "s3-events-example",
      "classifier_config": {
        "enable_custom_metrics": true,
        "log_level": "info",
        "log_retention_days": 14,
        "memory": 128,
        "timeout": 60
      },
      "data_sources": {
        "s3": {
          "bucket_name_01": [
            "cloudtrail"
          ],
          "bucket_name_02": [
            "cloudtrail"
          ]
        }
      },
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
        }
      }
    }

This configures the two buckets (``bucket_name_01`` and ``bucket_name_02``) to notify the classifier
function in this cluster when new objects arrive in the bucket at the specified (optional) prefix(es),
provided the objects have the specified (optional) suffix(es). Additionally, this will authorize the
classifier to download objects from each bucket.


Options
-------
The ``s3_events`` module expects a *dictionary/map* of bucket names, where the value for each key
(bucket name) is a list of maps. Each map in the list can include optional prefixes (``filter_prefix``)
and suffixes (``filter_suffix``) to which the notification should be applied. The mere existence of a
bucket name in this map within this module implicitly enables event notifications for said bucket.
Note that the value specified for the map of prefixes and suffixes can be an empty list (``[]``).
An empty list will enable event notifications for **all** objects created in the bucket by default.

See the above :ref:`example <s3_event_example>` for how prefixes/suffixes can be (optionally)
specified (as in "bucket_name_01") and how to use the empty list to enable bucket-wide
notifications (as in "bucket_name_02").
