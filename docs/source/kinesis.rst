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

Kinesis
~~~~~~~

Kinesis Streams settings for each cluster:

.. code-block:: json

  {
    "kinesis": {
      "streams": {
        "retention": 36,
        "shards": 5
      }
    }
  }

Options
~~~~~~~

=============  =========  ===========
Key            Required   Description
-------------  ---------  -----------
``retention``  ``Yes``    The data record retention period of your stream.
``shards``     ``Yes``    A shard provides a fixed unit of capacity to your stream.
=============  =========  ===========

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

  $ python stream_alert_cli.py terraform build --target kinesis
