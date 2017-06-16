Kinesis Streams
===============

Overview
--------

* StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion from `datasources <datasources.html>`_
* A Kinesis Stream is created for each `cluster <clusters.html>`_ you define.
* `Key concepts <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html>`_

At a high-level:

* A Kinesis Stream is created for each cluster you define
* A Kinesis Stream is composed of one or more shards
* The number of shards you choose is dependent on your data volume (see Concepts & Limits)
* Retention determines how long data is accessible on the stream itself; since StreamAlert is near real-time, the period can remain at the default of 24 hours
* Use Kinesis Firehose for retention of data for audit purposes or historical search

Limits
------

* `Kinesis Streams Limits`_
* `Kinesis Streams PUT Limits`_

.. _Kinesis Streams Limits: https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html
.. _Kinesis Streams PUT Limits: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html

Fields
------

The following configuration settings are defined in each cluster file (``conf/clusters/cluster-name.json``)

kinesis
~~~~~~~

Kinesis Streams settings for each cluster::

  "kinesis": {
    "streams": {
      "retention": 36,
      "shards": 5
    }
  }

options
~~~~~~~

=============     ========     ======================
Key               Required     Description
-------------     ---------    ----------
``retention``     ``true``     The data record retention period of your stream.
``shards``        ``true``     A shard provides a fixed unit of capacity to your stream. 
=============     =========    ======================

Kinesis Firehose
================

Overview
--------

* StreamAlert supports using AWS Kinesis Firehose for storing incoming data into an S3 bucket; a separate S3 bucket is created for each `cluster <clusters.html>`_ you define
* This can be utilized for long-term persistence, an audit trail, or historical search (soon)
* Agents/code must send to both AWS Kinesis Streams and AWS Kinesis Firehose for this to work

Limits
------

* `Kinesis Firehose Limits`_

.. _Kinesis Firehose Limits: https://docs.aws.amazon.com/firehose/latest/dev/limits.html

Fields
------

The following configuration settings are defined in each cluster file (``conf/clusters/cluster-name.json``)

firehose
~~~~~~~~

Example::

  "kinesis": {
    "firehose": {
      "enabled": true,
      "s3_bucket_suffix": "streamalert.results"
    }
  }

options
~~~~~~~

================     ========     ======================
Key                  Required     Description
----------------     ---------    ----------
``enabled``          ``true``     If set to ``false``, will not create a Kinesis Firehose
``s3_bucket_suffix`` ``true``     The suffix of the S3 bucket used for Kinesis Firehose data. The naming scheme is: ``prefix.cluster.suffix``
================     =========    ======================
