Datasource Configuration
========================

For background on supported datasource types, read `datasources <datasources.html>`_.

Overview
--------

Datasources defined in ``conf/sources.json`` control which datasources can send to and be analyzed by StreamAlert.

Each datasource (``kinesis``, ``s3``, or ``sns``) contains a mapping of specific resource names (kinesis stream names, s3 bucket IDs) along with a list of logs coming from that source.

Log schemas are defined in one or more files in the ``conf/schemas`` directory.

An example of this would be to put all carbonblack schemas into ``conf/schemas/carbonblack.json``.

Each log in the list of ``logs`` dictates to StreamAlert how to parse incoming data from a given resource.  Data will only be analyzed if its type is defined here.

Example:

.. code-block:: json

  {
    "kinesis": {
      "abc_corporate_streamalert": {
        "logs": [
          "box",
          "pan"
        ]
      },
      "abc_production_stream_streamalert": {
        "logs": [
          "inspec",
          "osquery"
        ]
      }
    },
    "s3": {
      "abc.webserver.logs": {
        "logs": [
          "nginx"
        ]
      },
      "abc.hids.logs": {
        "logs": [
          "carbonblack"
        ]
      }
    },
    "sns": {
      "abc_sns_topic": {
        "logs": [
          "logstash"
        ]
      }
    }
  }

Once datasources are defined, associated ``logs`` must have defined `schemas <conf-schemas.html>`_
