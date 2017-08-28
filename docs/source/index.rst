StreamAlert
===========

.. image:: ../images/sa-banner.png
  :align: center
  :alt: StreamAlert

StreamAlert is a serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define.

For more details, see our `announcement post <https://medium.com/@airbnbeng/e8619e3e5043>`_.

At a high-level
---------------

* Deployment is automated: simple, safe and repeatable for any AWS account
* Easily scalable from megabytes to terabytes per day
* Infrastructure maintenance is minimal, no devops expertise required
* Infrastructure security is a default, no security expertise required
* Supports data from different environments (ex: IT, PCI, Engineering)
* Supports data from different environment types (ex: Cloud, Datacenter, Office)
* Supports different types of data (Ex: JSON, CSV, Key-Value, and Syslog)
* Supports different use-cases like security, infrastructure, compliance and more

Components
----------

.. figure:: ../images/sa-high-level-arch.png
  :alt: StreamAlert High Level Architecture
  :align: center
  :target: _images/sa-high-level-arch.png

  (Click figure to enlarge)

Other Links
-----------

* `Github <https://github.com/airbnb/streamalert>`_
* `Twitter (unofficial) <https://twitter.com/streamalert_io>`_
* `Slack (unofficial) <https://streamalert.herokuapp.com>`_

.. note:: Docs are under construction, don't mind the dust!


Table of Contents
=================

.. _introduction:

.. toctree::
   :maxdepth: 2
   :caption: Introduction

   overview
   benefits
   requirements
   datatypes
   alternatives
   roadmap
   faq

.. _getting-started:

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started
   deployment
   deploy-rollback

.. _data_configuration:

.. toctree::
   :maxdepth: 2
   :caption: Data Config

   datasources
   conf-datasources
   conf-schemas
   conf-schemas-examples

.. _infra_configuration:

.. toctree::
   :maxdepth: 2
   :caption: Infrastructure Config

   account
   clusters
   kinesis
   lambda

.. _user_guide:

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   rules
   rule-testing
   outputs
   metrics
   troubleshooting
   report-bugs-features
   questions

.. _historical_search:

.. toctree::
  :maxdepth: 2
  :caption: Historical Search

  athena-setup
  athena-deploy
  athena-user-guide
  firehose
