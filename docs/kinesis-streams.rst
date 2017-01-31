Kinesis Streams
===============

Overview
--------

* StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion from `datasources <datasources.html>`_
* A Kinesis Stream is created for each `cluster <clusters.html>`_ you define.
* `Key concepts`_

.. _key concepts: https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html

Limits
------

* `Kinesis Streams Limits`_
* `Kinesis Streams PUT Limits`_

.. _Kinesis Streams Limits: https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html
.. _Kinesis Streams PUT Limits: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html

Fields
------

The following configuration settings are defined in ``variables.json``

kinesis_settings
~~~~~~~~~~~~~~~~

Example::

    "kinesis_settings": {
        "corporate": [    # cluster name
            1,            # number of shards
            24            # retention
        ],
        "production": [
            20,
            24
        ],
        ...
    },

At a high-level:

* A Kinesis Stream is created for each cluster you define
* A Kinesis Stream is composed of one or more shards
* The number of shards you choose is dependent on your data volume (see Concepts & Limits)
* Retention determines how long data is accessible on the stream itself; since StreamAlert is near real-time, the period can remain at the default of 24 hours
* Use Kinesis Firehose for retention of data for audit purposes or historical search









