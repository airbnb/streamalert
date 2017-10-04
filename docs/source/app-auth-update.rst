Updating an App's credentials
=============================

Overview
--------

You may need to change an App's credentials due to internal rotation policies or otherwise. The StreamAlert CLI allows you to easily update App credentials.
to aid in this process, the CLI also give you the ability to list currently configured Apps.

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


Updating App Credentials
----------------------------

To update an App's credentials, run the the following command:

.. code-block:: bash

  $ python manage.py app update-auth --cluster <cluster> --name <app_name>


This will have you follow a process similar to `configuring a new App <app-configuration.html#example-prompts-for-duo-auth>`_.
