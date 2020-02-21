#############
Lookup Tables
#############
LookupTables is a framework for injecting additional data into StreamAlert Lambda functions. LookupTables
offers a unified key-value interface into a set of backend storage solutions, allowing StreamAlert Lambda functions
to use state from outside of the raw telemetry that they receive.

With LookupTables, StreamAlert can hydrate alerting data, add statefulness to alerts, scalable pull down remote data, rapidly
tune rule logic, and much more!


*************************
How do LookupTables work?
*************************
LookupTables provides unified Python interface into backend data storage mechanisms. The two currently supported storage
solutions are Amazon S3 and Amazon DynamoDB.

LookupTables makes these storage solutions available to StreamAlert's Lambda functions. It is available on all
classifiers, the rules engine, the alert merger, and the alert processor.


*****
Usage
*****
Pulling keys from LookupTables is very easy!

.. code-block:: python

  from streamalert.shared.lookup_tables.core import LookupTables

  value = LookupTables.get('my-table', 'my-key', 'default-value')

The three arguments are as follows

1) Table Name — The name of the LookupTable. This is specified in the config (below).
2) Key — A key on the given LookupTable.
3) Default Value — If the key is not found, this value will be returned instead. Notably, *if the key is empty*
   the empty value will be returned, **NOT** this default value.


*************
Configuration
*************
LookupTables is configured via a single file, ``conf/lookup_tables.json``.

.. code-block::

  {
    "enabled": false,
    "tables": {
      "my-table-1": {
        "driver": "dynamodb",
        "table": "dynamodb-table-name",
        "partition_key": "partition-key",
        "value_key": "value-column",
        "cache_maximum_key_count": 3,
        "cache_refresh_minutes": 3,
        "consistent_read": false
      },
      "my-table-2": {
        "driver": "s3",
        "bucket": "s3-bucket-name",
        "key": "file.json",
        "compression": false,
        "cache_refresh_minutes": 10
      }
    }
  }

* ``enabled`` — (bool) Pass `true` to activate LookupTables. Leave `false` to disable.
* ``tables`` — (dict) A dict mapping the name of a LookupTable to its corresponding configuration.
  The exact configuration varies from driver to driver. See below:


S3 Driver
=========
This uses Amazon S3. It stores all LookupTables data into a single file in an S3 bucket, specified in the
configuration:

.. code-block::

  {
    "driver": "s3",
    "bucket": "airbnb.sample.lookuptable",
    "key": "resource_map.json.gz",
    "compression": "gzip",
    "cache_refresh_minutes": 10
  }

* ``driver`` — (str) Use ``s3``
* ``bucket`` — (str) The name of the S3 bucket. It must be in the same AWS account. NOTE: Multiple S3 LookupTables
  can use the same bucket, as long as they reference different ``key``'s.
* ``key`` — (str) The S3 object key (aka filename) in the bucket.
* ``compression`` — (str|bool) The compression algorithm of the S3 object. Currently only supports ``gzip``.
  Pass ``false`` if the object is not compressed and is stored as JSON plaintext.
* ``cache_refresh_minutes`` — (int) Number of minutes to cache the entire table. See the `caching <#Caching>` section below.


The Nitty Gritty
----------------
Because S3 driver stores all data in a single S3 file, it loads the **entire table** upfront. This is beneficial
to StreamAlert code that scans multiple keys back-to-back, as only a single HTTP call will be made to S3, and
subsequent calls will be made to the caching layer.

On the other hand, because the entire S3 file is loaded into memory, large S3 files can risk running into the
memory ceiling of StreamAlert's Lambda functions.


DynamoDB Driver
===============
This driver uses DynamoDB as the storage layer. This driver stores individual keys as discrete rows on the DynamoDB
table. The DynamoDB driver can be configured to respect both tables with a single partition key, as well as tables
with both a partition and a sort key.

.. code-block::

  {
    "driver": "dynamodb",
    "table": "some_table_name",
    "partition_key": "MyPartitionKey",
    "sort_key": "MySortKey",
    "value_key": "MyValueKey",
    "consistent_read": false,
    "key_delimiter": ":",
    "cache_refresh_minutes": 2,
    "cache_maximum_key_count": 10
  }

* ``driver`` — (str) Use ``dynamodb``
* ``table`` — (str) The name of the DynamoDB table. This table must be on the same AWS region as the StreamAlert deployment.
* ``partition_key`` — (str) The name of the partition key. The partition key MUST be a string type.
* ``sort_key`` — (str) (Optional) The name of the sort key, if one exists. The sort key MUST be a string type.
* ``value_key`` — (str) The name of the value column. NOTE: Multiple LookupTables can be "overlapped" on a single DynamoDB table,
  using different ``value_key``'s.
* ``consistent_read`` — (bool) (Optional) When ``true``, it forces DynamoDB queries to be strongly consistent. This reduces performance,
  (potentially increasing HTTP latency during dynamo calls), but guarantees that modified values to LookupTables will be immediately
  available. Passing ``false`` allows eventually consistent reads, which can greatly improve performance.
* ``key_delimiter`` — (str) (Optional) When accessing keys in a DynamoDB LookupTable that uses both a ``partition_key`` and a
  ``sort_key``, the syntax of the final key is ``{partition_key}{delimiter}{sort_key}``. The default delimiter is a
  colon (``:``), but this parameter can be provided to offer a different delimiter.
* ``cache_refresh_minutes`` — (int) Number of minutes to cache each individual key.
* ``cache_maximum_key_count`` — (int) Maximum number of keys to cache on this LookupTable. Once the cache is full, keys
  will be evicted on a random-selection basis.


The Nitty Gritty
----------------
The DynamoDB driver is designed to retrieve a minimal amount of data per request. This reduces the memory footprint
compared to the S3 driver, and can reduce the Lambda memory limit required to prevent out-of-memory errors.

As a tradeoff, rapid back-to-back accesses of different keys will result in many HTTP calls being made to DynamoDB,
which can slow down StreamAlert's Lambda execution.


Caching
=======
To reduce redundant requests to storage layers, LookupTables offers a simple in-memory caching layer.
It can be configured using the ``cache_refresh_minutes`` configuration setting under each driver.

This will persist data retrieved from the storage solutions for a number of minutes in memory. This can
increase Lambda memory consumption, but can also reduce runtime by reducing number of HTTP calls.


******************************
Putting Data Into LookupTables
******************************
It is **not** advisable (yet) for StreamAlert Lambdas to write values into LookupTables. It is generally
advisable for external Lambdas (or other processes) to manage the data in LookupTables.


CLI Management
==============
There is a StreamAlert CLI command for managing LookupTables, ``python manage.py lookup-tables``, with three subcommands:

* ``describe-tables``
* ``get``
* ``set``

Use the ``-h`` flag to learn how to use them.


**************
Best Practices
**************
This section documents several best practices in no particular order.


Organize LookupTables Data
==========================
While LookupTables *can* support storage of whatever-data in whatever-table using whatever-key, for usage
patterns that push scaling limits, it is generally advisable to organize data into tables that optimize
for their access patterns.

It is advisable to split the data into many LookupTables, each containing data of similar access patterns.


When to use S3, and when to use Dynamo
======================================
Because it can condense the entire data fetching process into a single HTTP request, the S3 driver functions
most optimally with small data sets that are often accessed together or interdependently. It is generally
inadvisable to store massive amounts of data on a single S3 file.

S3 is ideal for "table scan" types of data. For example, long lists of IP addresses, whitelists, or dict mappings
of hosts to metadata. S3 is also ideal for data that is often used together.


Caching Best Practices
======================
Really, we haven't found any reason to stress out about these values. Setting 5 minutes or 10 minutes is
enough.

More effective is to use the DynamoDB driver with ``cache_maximum_key_count``. This allows more fine-grained
control of the maximum memory consumption of the cache.


Prefer Eventually Consistent Reads
==================================
We **strongly** recommend allowing eventually consistent reads on the DynamoDB driver. The public SLA for
eventually consistent reads is 20 seconds, with a typical delay of less than 3 seconds.


**********
Deployment
**********
When LookupTables are configured properly, a subsequent run of ``python manage.py generate`` or ``python manage.py build``
will create a new file: ``terraform/lookup_tables.tf.json`` and build the appropriate *IAM PERMISSIONS* for
the StreamAlert Lambdas to access them.

It **will not** build the actual S3 buckets or DynamoDB tables, however. Those resources have to be built elsewhere.


***********
Usage Ideas
***********

Whitelist
=========
Instead of placing whitelists inline in code:

.. code-block:: python

  IP_WHITELIST = [
    '2.2.2.2',
    '8.8.8.8',
    '8.0.8.0',
  ]

Consider using LookupTables:

.. code-block:: python

  IP_WHITELIST = LookupTables.get('whitelists', 'ip_whitelist', [])


External Configuration
======================
Suppose StreamAlert receive a piece of telemetry that includes a hostname:

.. code-block::

  {
    "hostname": "securityiscool.airbnb.com",
    ...
  }

But suppose the rules logic requires an IP address instead. LookupTables can be used to retrieve realtime information
about the DHCP or DNS information about that hostname, even if the IP address is not available in the original telemetry.

.. code-block:: python

  @rule(
    # ...
  )
  def my_rule(rec):
    hostname = get_key(rec, 'hostname')
    dns_metadata = LookupTables.get('dns_information', 'host:{}'.format(hostname), {})
    # rules logic here...
