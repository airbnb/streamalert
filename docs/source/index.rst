.. streamalert documentation master file, created by
   sphinx-quickstart on Mon Jan 23 21:19:26 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

StreamAlert
=======================================

StreamAlert is a serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define.

For more details, see our announcement post: https://medium.com/@airbnbeng/e8619e3e5043

At a high-level:

* Deployment is automated: simple, safe and repeatable for any AWS account
* Easily scalable from megabytes to terabytes per day
* Infrastructure maintenance is minimal, no devops expertise required
* Infrastructure security is a default, no security expertise required
* Supports data from different environments (ex: IT, PCI, Engineering)
* Supports data from different environment types (ex: Cloud, Datacenter, Office)
* Supports different types of data (Ex: JSON, CSV, Key-Value, and Syslog)
* Supports different use-cases like security, infrastructure, compliance and more


Table of Contents
=======================================

.. _introduction:

.. toctree::
   :maxdepth: 2
   :caption: Introduction

   overview
   benefits
   requirements
   datasources
   datatypes
   rules
   outputs
   alternatives
   roadmap
   faq

.. _data_configuration:

.. toctree::
   :maxdepth: 2
   :caption: Data Configuration

   conf-datasources
   conf-schemas

.. _infra_configuration:

.. toctree::
   :maxdepth: 2
   :caption: Infrastructure Configuration

   account
   clusters
   kinesis-streams
   kinesis-firehose
   lambda
   secrets

.. _deployment:

.. toctree::
   :maxdepth: 2
   :caption: Deployment

   installation
   deploying
   deploy-rollback

.. _user_guide:

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   metrics
   troubleshooting
   report-bugs-features
   questions

