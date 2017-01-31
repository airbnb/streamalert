Datasources
===========

Overview
--------

Datasources are defined in ``conf/sources.json``

Example::

    {
      "kinesis": {                 # define each kinesis stream w/respective logs
        "abc_corporate_stream": {  # kinesis stream name
          "logs": [                # expected log types
            "box",
            "pan"
          ]
        },
        "abc_production_stream": {
          "logs": [
            "inspec",
            "osquery"
          ]
        },
        ...
      },
      "s3": {                      # define each s3 bucket w/respective logs
        "abc.webserver.logs": {    # s3 bucket name
          "logs": [                # expected log types
            "nginx"
          ]
        },
        "abc.hids.logs": {
          "logs": [
            "carbonblack"
          ]
        },
        ...
      }
    }

Once datasources are defined, associated ``logs`` must have defined `schemas <conf-schemas.html>`_
