###############
Global Settings
###############
Settings that apply *globally* for StreamAlert are stored in the ``conf/global.json`` file. This
file has a few different sections to help organize the settings by purpose. These sections are
described in further detail below.


*******
Account
*******
The ``account`` section of ``conf/global.json`` file is used to store information specifically
related to the AWS account used for your StreamAlert deployment.


Configuration
=============
.. code-block:: json

  {
    "account": {
      "aws_account_id": "123456789012",
      "prefix": "<prefix>",
      "region": "us-east-1"
    }
  }


Options
-------
===================  ============  ==============  ===============
**Key**              **Required**  **Default**     **Description**
-------------------  ------------  --------------  ---------------
``aws_account_id``   Yes           ``None``        12 digit account ID for your AWS account
``prefix``           Yes           ``None``        An alphanumeric and unique prefix to be used for your deployment
``region``           Yes           ``us-east-1``   AWS region within which you would like to deploy StreamAlert
===================  ============  ==============  ===============

.. tip::

  The ``aws_account_id`` and ``prefix`` settings can be set using the CLI:

  .. code-block:: bash

    python manage.py configure aws_account_id 111111111111  # Replace with your 12-digit AWS account ID
    python manage.py configure prefix <value>               # Choose a unique name prefix (alphanumeric characters only)

  However, if a different `region` is desired, it must be changed manually.


*******
General
*******
The ``general`` section of ``conf/global.json`` file is used to store general information related
to your StreamAlert deployment. Notably, paths to ``rules`` and ``matchers`` can be supplied here.


Configuration
=============
.. code-block:: json

  {
    "general": {
      "terraform_files": [
        "/absolute/path/to/extra/terraform/file.tf"
      ],
      "matcher_locations": [
        "matchers"
      ],
      "rule_locations": [
        "rules"
      ],
      "scheduled_query_locations": [
        "scheduled_queries"
      ],
      "publisher_locations": [
        "publishers"
      ],
      "third_party_libraries": [
        "pathlib2==2.3.5"
      ]
    }
  }


Options
-------
=============================  =============  =========================  ===============
**Key**                        **Required**   **Default**                **Description**
-----------------------------  -------------  -------------------------  ---------------
``matcher_locations``          Yes            ``["matchers"]``           List of local paths where ``matchers`` are defined
``rule_locations``             Yes            ``["rules"]``              List of local paths where ``rules`` are defined
``scheduled_query_locations``  Yes            ``["scheduled_queries"]``  List of local paths where ``scheduled_queries`` are defined
``publisher_locations``        Yes            ``["publishers"]``         List of local paths where ``publishers`` are defined
``third_party_libraries``      No             ``["pathlib2==2.3.5"]``    List of third party dependencies that should be installed via ``pip`` at deployment time. These are libraries needed in rules, custom code, etc that are defined in one of the above settings.
``terraform_files``            No             ``[]``                     List of local paths to Terraform files that should be included as part of this StreamAlert deployment
=============================  =============  =========================  ===============


**************
Infrastructure
**************
The ``infrastructure`` section of ``conf/global.json`` file is used to store information related
to settings for various global resources/infrastructure components needed by StreamAlert. There are
various subsections within this section, each of which is outlined below.


Alerts Firehose
===============
By default, StreamAlert will send all alert payloads to S3 for historical retention and searching.
These payloads include the original record data that triggered the alert, as well as the rule that
was triggered, the source of the log, the date/time the alert was triggered, the cluster from
which the log came, and a variety of other fields.


.. _alerts_firehose_configuration:

Configuration
-------------
The following ``alerts_firehose`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "alerts_firehose": {
        "bucket_name": "<prefix>-streamalerts",
        "buffer_size": 64,
        "buffer_interval": 300,
        "cloudwatch_log_retention": 14
      }
    }
  }


Options
^^^^^^^
=============================  ============  ==========================  ===============
**Key**                        **Required**  **Default**                 **Description**
-----------------------------  ------------  --------------------------  ---------------
``bucket_name``                No            ``<prefix>-streamalerts``   Bucket name to override the default name
``buffer_size``                No            ``64`` (MB)                 Buffer incoming data to the specified size, in megabytes,
                                                                         before delivering it to S3
``buffer_interval``            No            ``300`` (seconds)           Buffer incoming data for the specified period of time, in
                                                                         seconds, before delivering it to S3
``cloudwatch_log_retention``   No            ``14`` (days)               Days for which to retain error logs that are sent to CloudWatch
                                                                         in relation to this Kinesis Firehose Delivery Stream
=============================  ============  ==========================  ===============


Alerts Table
============
StreamAlert utilizes a DynamoDB Table as a temporary storage mechanism when alerts are triggered
from the Rules Engine. This table can be configured as necessary to scale to the throughput of
your alerts.


Configuration
-------------
The following ``alerts_table`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "alerts_table": {
        "read_capacity": 10,
        "write_capacity": 10
      }
    }
  }


Options
^^^^^^^
===================  ============  ===========  ===============
**Key**              **Required**  **Default**  **Description**
-------------------  ------------  -----------  ---------------
``read_capacity``    No            ``5``        Read capacity value to apply to the alerts DynamoDB Table
``write_capacity``   No            ``5``        Write capacity value to apply to the alerts DynamoDB Table
===================  ============  ===========  ===============


Classifier SQS
==============
StreamAlert sends all classified logs to an SQS Queue. This queue is then read from by the Rules
Engine function to perform rule analysis.


Configuration
-------------

.. note::

  These configuration options are only available for legacy purposes and may be removed in
  a future release. They will typically only be needed if manually migrating from v2 to v3+.

The following ``classifier_sqs`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "classifier_sqs": {
        "use_prefix": true
      }
    }
  }


Options
^^^^^^^
===============  ============  ===========  ===============
**Key**          **Required**  **Default**  **Description**
---------------  ------------  -----------  ---------------
``use_prefix``   No            ``true``     Whether the prefix should be prepended to the classified
                                            logs SQS Queue that is created (set to ``false`` for
                                            legacy purposes only)
===============  ============  ===========  ===============


.. _firehose_configuration:

Firehose (Historical Data Retention)
====================================
StreamAlert also supports sending all logs to S3 for historical retention and searching based on
classified type of the log. Kinesis Data Firehose Delivery Streams are used to send the data to S3.


Configuration
-------------
The following ``firehose`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. _firehose_example_01:

.. code-block:: json

  {
    "infrastructure": {
      "firehose": {
        "enabled": true,
        "bucket_name": "<prefix>-streamalert-data",
        "buffer_size": 64,
        "buffer_interval": 300,
        "enabled_logs": {
          "osquery": {
            "enable_alarm": true
          },
          "cloudwatch:cloudtrail": {},
          "ghe": {
            "enable_alarm": true,
            "evaluation_periods": 10,
            "period_seconds": 3600,
            "log_min_count_threshold": 100000
          }
        }
      }
    }
  }


Options
^^^^^^^
=======================  ============  ==============================  ===============
**Key**                  **Required**  **Default**                     **Description**
-----------------------  ------------  ------------------------------  ---------------
``enabled``              Yes           ``None``                        If set to ``false``, this will disable the creation of any Kinesis Firehose
                                                                       resources and indicate to the Classifier functions that they should not send
                                                                       data for retention
``use_prefix``           No            ``true``                        Whether the prefix should be prepended to Firehoses that are created (only to be used for legacy purposes)
``bucket_name``          No            ``<prefix>-streamalert-data``   Bucket name to override the default name
``buffer_size``          No            ``64`` (MB)                     Buffer incoming data to the specified size, in megabytes, before delivering it to S3
``buffer_interval``      No            ``300`` (seconds)               Buffer incoming data for the specified period of time, in seconds, before delivering it to S3
``enabled_logs``         No            ``{}``                          Which classified log types to send to Kinesis Firehose from the Classifier
                                                                       function, along with specific settings per log type
=======================  ============  ==============================  ===============

.. note::

  The ``enabled_logs`` object should contain log types for which Firehoses should be created.
  The keys in the 'dictionary' should reference the log type (or subtype) for which Firehoses
  should be created, and the value should be additional (optional) settings per log type. The
  following section contains more detail on these settings.


Configuring ``enabled_logs``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The ``enabled_logs`` section of the ``firehose`` settings must explicitly specify the log types for
which you would like to enable historical retention. There are two syntaxes you may use to specify
log types:

  1. parent log type: ``osquery``
  2. log subtype: ``osquery:differential``

The former will create Firehose resources for *all* ``osquery`` subtypes, while the latter
will only create one Firehose for specifically the ``osquery:differential`` subtype.

Since each Firehose that gets created can have additional settings applied to it, the proper way to
simply *enable* given log types is to add items to ``enabled_logs`` as follows (**note the empty
JSON object as the value**):

.. _firehose_example_02:

.. code-block:: json

  {
    "infrastructure": {
      "firehose": {
        "enabled_logs": {
          "osquery": {},
          "cloudwatch:cloudtrail": {}
        }
      }
    }
  }


Each Firehose that is created can be configured with an alarm that will fire when the incoming
log volume drops below a specified threshold. This is disabled by default, and can be enabled
by setting ``enable_alarm`` to ``true`` within the configuration for the log type.

============================  ============  ==============================================  ===============
**Key**                       **Required**  **Default**                                     **Description**
----------------------------  ------------  ----------------------------------------------  ---------------
``enable_alarm``              No            ``false``                                       If set to ``true``, a CloudWatch Metric Alarm will be created for this log type
``evaluation_periods``        No            ``1``                                           Consecutive periods the records count threshold must be breached before triggering an alarm
``period_seconds``            No            ``86400``                                       Period over which to count the IncomingRecords (default: 86400 seconds [1 day])
``log_min_count_threshold``   No            ``1000``                                        Alarm if IncomingRecords count drops below this value in the specified period(s)
``alarm_actions``             No            ``<prefix>_streamalert_monitoring SNS topic``   Optional CloudWatch alarm action or list of CloudWatch alarm actions (e.g. SNS topic ARNs)
============================  ============  ==============================================  ===============

.. note::

  See the ``ghe`` log type in the :ref:`example <firehose_example_01>` ``firehose`` configuration above for how this can be performed.


Additional Info
^^^^^^^^^^^^^^^
When adding a log type to the ``enable_logs`` configuration, a dedicated Firehose is created for
each of the log subtypes.

For instance, suppose the following schemas are defined across one or more files in the ``conf/schemas`` directory:

.. code-block:: json

  {
    "cloudwatch:events": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "cloudwatch:cloudtrail": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "osquery:differential": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "osquery:status": {
      "parser": "json",
      "schema": {"key": "type"}
    }
  }

Supposing also that the above ``enabled_logs`` :ref:`example <firehose_example_02>` is used, the
following Firehose resources will be created:

* ``<prefix>_streamalert_cloudwatch_cloudtrail``
* ``<prefix>_streamalert_osquery_differential``
* ``<prefix>_streamalert_osquery_status``

.. note::

  Notice that there is no Firehose created for the ``cloudwatch:events`` log type. This is because
  this log type was not included in the ``enabled_logs`` configuration, and only the
  ``cloudwatch:cloudtrail`` subtype of ``cloudwatch`` was included.

Each Delivery Stream delivers data to the same S3 bucket created by the module in a prefix based on the corresponding log type:

* ``arn:aws:s3:::<prefix>-streamalert-data/cloudwatch_cloudtrail/YYYY/MM/DD/data_here``
* ``arn:aws:s3:::<prefix>-streamalert-data/osquery_differential/YYYY/MM/DD/data_here``
* ``arn:aws:s3:::<prefix>-streamalert-data/osquery_status/YYYY/MM/DD/data_here``


Limits
""""""
Depending on your log volume, you may need to request limit increases for Firehose.
* `Kinesis Firehose Limits <https://docs.aws.amazon.com/firehose/latest/dev/limits.html>`_
* `Kinesis Firehose Delivery Settings <http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html>`_


Monitoring
==========
StreamAlert can send notifications of issues with infrastructure to an SNS topic (aka "monitoring"
the health of your infrastructure).


Configuration
-------------
The following ``monitoring`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "monitoring": {
        "sns_topic_name": "name-of-existing-sns-topic-to-use"
      }
    }
  }


Options
^^^^^^^
===================  ============  ====================================  ===============
**Key**              **Required**  **Default**                           **Description**
-------------------  ------------  ------------------------------------  ---------------
``sns_topic_name``   No            ``<prefix>_streamalert_monitoring``   Name of an existing SNS Topic to which monitoring information
                                                                         should be sent instead of the default one that will be created
===================  ============  ====================================  ===============


Rule Staging
============
StreamAlert comes with the ability to *stage* rules that have not been battle tested. This
feature is backed by a DynamoDB table, for which there are a few configurable options.

Configuration
-------------
.. code-block:: json

  {
    "infrastructure": {
      "rule_staging": {
        "cache_refresh_minutes": 10,
        "enabled": true,
        "table_read_capacity": 5,
        "table_write_capacity": 5
      }
    }
  }


Options
^^^^^^^
==========================  ============  ===========  ===============
**Key**                     **Required**  **Default**  **Description**
--------------------------  ------------  -----------  ---------------
``enabled``                 No            ``false``    Should be set to ``true`` to enable the rule staging feature
``cache_refresh_minutes``   No            ``10``       Maximum amount of time (in minutes) the Rules Engine function
                                                       should wait to force refresh the rule staging information.
``table_read_capacity``     No            ``5``        DynamoDB read capacity to allocate to the table that stores staging
                                                       information. The default setting should be sufficient in most use cases.
``table_write_capacity``    No            ``5``        DynamoDB write capacity to allocate to the table that stores staging
                                                       information. The default setting should be sufficient in most use cases.
==========================  ============  ===========  ===============

.. tip::

  By default, the rule staging feature is not enabled. It can be enabled with the following command:

  .. code-block:: bash

    python manage.py rule-staging enable --true


S3 Access Logging
=================
StreamAlert will send S3 Server Access logs generated by all the buckets in your deployment to a
logging bucket that will be created by default. However, if you have an existing bucket where you
are already centralizing these logs, the name may be provided for use by StreamAlert's buckets.


Configuration
-------------
The following ``s3_access_logging`` configuration settings can be defined within the
``infrastructure`` section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "s3_access_logging": {
        "bucket_name": "name-of-existing-bucket-to-use"
      }
    }
  }


Options
^^^^^^^
================  ============  ====================================  ===============
**Key**           **Required**  **Default**                           **Description**
----------------  ------------  ------------------------------------  ---------------
``bucket_name``   No            ``<prefix>-streamalert-s3-logging``   Name of existing S3 bucket to use for logging instead of
                                                                      the default bucket that will be created
================  ============  ====================================  ===============


*********
Terraform
*********
StreamAlert uses Terraform for maintaining its infrastructure as code and Terraform will utilize a
remote state that is stored on S3. By default, we will create a bucket for use by Terraform, but
a bucket name can also be supplied to use instead. The ``terraform`` section of ``conf/global.json``
file should be used to store these settings.


Configuration
=============
.. code-block:: json

  {
    "terraform": {
      "bucket_name": "<prefix>-streamalert-terraform-state",
      "state_key_name": "streamalert_state/terraform.tfstate"
    }
  }


Options
-------
===================  ============  =========================================  ===============
**Key**              **Required**  **Default**                                **Description**
-------------------  ------------  -----------------------------------------  ---------------
``bucket_name``      No            ``<prefix>-streamalert-terraform-state``   Name of existing S3 bucket to use for the Terraform
                                                                              remote state instead of the default bucket that will be created
``state_key_name``   No            ``streamalert_state/terraform.tfstate``    Name to use as the key of the Terraform state object in S3
===================  ============  =========================================  ===============
