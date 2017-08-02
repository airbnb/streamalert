#! /bin/bash
nosetests test/unit \
--with-coverage \
--cover-package=stream_alert.rule_processor \
--cover-package=stream_alert.alert_processor \
--cover-package=stream_alert_cli \
--cover-package=stream_alert.athena_partition_refresh \
--cover-min-percentage=80 \
--cover-html \
--cover-html-dir=htmlcov