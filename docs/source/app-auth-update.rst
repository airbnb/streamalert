App Integration Auth Updating
=============================

Overview
--------

In the instance that the required authentication information for a configured App changes, it may be necessary to update a currently deployed App to reflect this.
To avoid having to remove the deployed App and add a new configuration just to get this updated information into production, StreamAlert's CLI
includes some commands to list apps and to update this information directly.

Listing Apps
------------

To list currently configured StreamAlert Apps (grouped by cluster), use the CLI command:

.. code-block:: bash

  $ python manage.py app list

This list will be empty for each cluster if no apps are configured, or will appear similar to the following::

  Cluster: prod

    Name: duo_prod_collector
      log_level:                     info
      interval:                      rate(2 hours)
      timeout:                       80
      memory:                        128
      current_version:               $LATEST
      type:                          duo_auth


Updating Authentication Info
----------------------------

To update a listed App configuration with new authentication information, use the following command:

.. code-block:: bash

  $ python manage.py app update-auth --cluster <cluster> --name <app_name>


The above command will walk through updating the authentication information, similar to the process when `configuring a new App <app-configuration.html#example-prompts-for-duo-auth>`_.
