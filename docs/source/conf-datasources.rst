Datasource Configuration
========================
.. note::

  As of release 3.0.0 data source configuration has moved
  from sources.json into the ``data_sources`` top level key for each your clusters.

For background on supported data source types, read `data sources <datasources.html>`_.

Overview
--------

Data sources defined in each cluster file in the ``conf/clusters`` directory under the ``data_sources`` top level key control which data sources can send to and be analyzed by StreamAlert.

Each data source (``kinesis``, ``s3``, or ``sns``) contains a mapping of specific resource names (kinesis stream names, s3 bucket IDs) along with a list of logs coming from that source.

Log schemas are defined in one or more files in the ``conf/schemas`` directory.

An example of this would be to put all carbonblack schemas into ``conf/schemas/carbonblack.json``.

Each log in the list of ``logs`` dictates to StreamAlert how to parse incoming data from a given resource.  Data will only be analyzed if its type is defined here.

Example:

.. code-block:: json

  {
    "data_sources": {
      "kinesis": {
        "abc_corporate_streamalert": [
          "box",
          "pan"
        ],
        "abc_production_stream_streamalert": [
          "inspec",
          "osquery"
        ]
      },
      "s3": {
        "abc.webserver.logs": [
            "nginx"
        ],
        "abc.hids.logs": [
          "carbonblack"
        ]
      },
      "sns": {
        "abc_sns_topic": [
          "logstash"
        ]
      }
    }
  }

Once data sources are defined, associated ``logs`` must have defined `schemas <conf-schemas.html>`_
