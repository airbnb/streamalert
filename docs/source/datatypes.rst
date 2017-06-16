Datatypes
=========

StreamAlert supports the following datatypes:

JSON::

  {"type": "json"}

CSV::

  csv,data,example

Key-Value::

  type=kv data=example

Syslog::

  Jun 15 00:00:40 host1.mydomain.io application[pid] syslog message.

And gzipped JSON, CSV, Syslog or Key-Value (only when ingested from S3)
