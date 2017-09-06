Athena User Guide
=================

Concepts
--------

* `SQL <https://www.w3schools.com/sql/sql_intro.asp>`_
* `Athena Partitions <http://docs.aws.amazon.com/athena/latest/ug/partitions.html>`_


Querying Data
-------------

After completion of the `Athena Setup <athena-setup.html>`_ and `Athena Deploy <athena-deploy.html>`_, alerts generated from StreamAlert are now searchable in the Athena UI.

To get started with querying of this data, navigate to the AWS Console, click Services, and type Athena.

When the service loads, switch the ``DATABASE`` option in the dropdown to ``streamalert``:

.. figure:: ../images/athena-usage-1.png
  :alt: StreamAlert Athena Database Selection
  :align: center
  :target: _images/athena-usage-1.png

To view the schema of the ``alerts`` table, click the eye icon:

.. figure:: ../images/athena-usage-2.png
  :alt: StreamAlert Athena Alerts Schema
  :align: center
  :target: _images/athena-usage-2.

To make a query, type a SQL statement in the Query Editor, and click Run Query:

.. figure:: ../images/athena-usage-3.png
  :alt: StreamAlert Athena Run Query
  :align: center
  :target: _images/athena-usage-3.

The query shown above will show the most recent 10 alerts.

Tips
----

Data is partitioned in the following format ``YYYY-MM-DD-hh-mm``.

An example is ``2017-08-01-22-00``.

To increase query performance, filter data within a specific partition or range of partitions.

With StreamAlert tables, the date partition is the ``dt`` column.

As an example, the query below counts all alerts during a given minute:

.. figure:: ../images/athena-usage-4.png
  :alt: StreamAlert Athena Run Query with Partition
  :align: center
  :target: _images/athena-usage-4.

For additional guidance on using SQL, visit the link under Concepts.
