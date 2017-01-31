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

The following configuration settings are defined in ``variables.json``

firehose_s3_bucket_suffix
~~~~~~~~~~~~~~~~~~~~~~~~~

Example::

    "firehose_s3_bucket_suffix": "streamalert.results",

This is the suffix used when naming/creating S3 buckets for each cluster.

The naming scheme is approximately: ``${prefix}.${cluster}.${suffix}``
