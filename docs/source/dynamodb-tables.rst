Alerts Table
============
StreamAlert utilizes a DynamoDB Table as a temporary storage mechanism when alerts are triggered
from the Rules Engine. This table can be configured as necessary to scale to the throughput of
your alerts.

Configuration
-------------
The following ``alerts_table`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "alerts_table": {
        "read_capacity": 10,
        "write_capacity": 10
      }
    }
  }


Options
~~~~~~~
=============================  ========  =======  ===========
Key                            Required  Default  Description
-----------------------------  --------  -------  -----------
``read_capacity``              ``No``    ``5``    Read capacity value to apply to the alerts DynamoDB Table
``write_capacity``             ``No``    ``5``    Write capacity value to apply to the alerts DynamoDB Table
=============================  ========  =======  ===========
