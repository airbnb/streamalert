###############
Troubleshooting
###############

********************
Kinesis Data Streams
********************
As detailed in other sections, StreamAlert utilizes Amazon Kinesis Data Streams.

Review Kinesis Streams `key concepts`_

.. _key concepts: https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html


Limits
======
* `Kinesis Data Streams Limits`_
* `Kinesis Data Streams PUT Limits`_

.. _Kinesis Data Streams Limits: https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html
.. _Kinesis Data Streams PUT Limits: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html


ThroughputExceeded
==================
Pertains to ``WriteProvisionedThroughputExceeded`` or ``ProvisionedThroughputExceededException``

The documentation above states:

* *"Each shard can support up to 1,000 records per second for writes, up to a maximum total data write rate of 1 MB per second (including partition keys)"*
* *"Each PutRecords request can support up to 500 records. Each record in the request can be as large as 1 MB, up to a limit of 5 MB for the entire request, including partition keys"*

If you're experiencing either error, one of the following holds true:

1. You are exceeding 1000 records/s write on at least one shard
2. You are exceeding 1MB/s on at least one shard
3. You sent > 500 records in a single PutRecords request
4. You sent a record > 1MB
5. You are sending > 5MB in a PutRecords request to at least one shard

\(1\),\(2\),\(5\) can be addressed by allocating more shards or using a partition key

\(3\) and \(4\) can be addressed by using code or agents with the proper limit checks

How you setup your partition keys depends on your use-cases, scale and how you're sending your data.

In our experience, there are three common use-cases:

* No partition key (small scale)
* Per-batch partition key (medium scale)
* Per-record partition key (larger scale)

Explanation: A `PutRecordsBatch` request can have up to 500 records amounting to a total of 5MB. If you're doing a per-batch partition key, that means you're attempting to send up to 5MB to a single shard that has a limit of 1MB/s. Keep in mind: if your code/agent uses splay or has reasonable retry logic, an error or exception does not imply data loss and may still be a viable strategy.

StreamAlert enables AWS `Enhanced Monitoring`_ to help you diagnose these types of issues via shard-level metrics. Simply go to ``CloudWatch`` -> ``Metrics`` -> ``Kinesis``. This also allows you to measure IncomingBytes and IncomingRecords.

.. _Enhanced Monitoring: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_EnableEnhancedMonitoring.html


DescribeStream: Rate exceeded
=============================
Or ``DescribeDeliveryStream: Rate exceeded.``

This API call is limited to 10 requests/s. Your agent/code should not be using this API call to determine if the Kinesis Stream is available to receive data. The agent/code should simply attempt to send the data and gracefully handle any exceptions.


certificate verify failed
=========================
Run the following command on the impacted host, choosing the correct region: ``openssl s_client -showcerts -connect kinesis.us-west-2.amazonaws.com:443``

If this returns ``Verify return code: 0 (ok)``, your agent/code needs to use Amazon's root and/or intermediate certificates (PEM) for TLS to function properly
