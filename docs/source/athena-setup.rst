Athena Setup
============

Overview
--------

AWS Athena is a Serverless query service used to analyze large volumes of data stored in S3.

Data in Athena is searchable via ANSI SQL and powered by Presto.

StreamAlert uses AWS Athena for historical searching of:

* Generated alerts from StreamAlert (currently supported)
* All incoming Data sent to StreamAlert (coming soon)

This works by:

* Creating a ``streamalert`` Athena database
* Creating Athena tables to read S3 data
* Using a Lambda function to periodically refresh Athena to make the data searchable

Concepts
--------
* AWS Athena `details`_
* AWS Athena `tables`_
* AWS Lambda `FAQ`_
* AWS Lambda `pricing`_

.. _details: https://aws.amazon.com/athena/details/
.. _tables: http://docs.aws.amazon.com/athena/latest/ug/creating-tables.html
.. _faq: https://aws.amazon.com/athena/faqs/
.. _pricing: https://aws.amazon.com/athena/pricing/

Getting Started
---------------

To get started with Athena, run the following commands:

.. code-block:: bash

  $ python manage.py athena init
  $ python manage.py athena enable

This will initialize and enable the configuration for StreamAlert's usage of Athena.

Next, create the ``streamalert`` database:

.. code-block:: bash

  $ python manage.py athena create-db

Create the ``alerts`` table for searching generated StreamAlerts:

.. code-block:: bash

  $ python manage.py athena create-table --type alerts --bucket <s3.bucket.id.goes.here>

Create tables for data sent to StreamAlert:

.. code-block:: bash

  $ python manage.py athena create-table \ 
    --type data \
    --bucket <prefix>.streamalert.data \
    --refresh_type add_hive_partition \
    --table_name <log_name>

Note: The log name above is representative of an enabled log source to your StreamAlert deployment.

For example, if you have 'cloudwatch' in your sources, you would want to create tables for all possible subtypes.  This includes ``cloudwatch_events`` and ``cloudwatch_flow_logs``.  Also notice that ``:`` is substituted with ``_``; this is due to Hive limitations on table names.

Repeat this process for all relevant data tables in your deployment.

Next Steps
----------

* `Configure and deploy the Athena Partition Refresher Lambda function <athena-deploy.html>`_
* `Configure and deploy Kinesis Firehose for delivery of data to S3 <firehose.html>`_
