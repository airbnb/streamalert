#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi
nosetests tests/unit \
--with-coverage \
--cover-package=app_integrations \
--cover-package=stream_alert.alert_processor \
--cover-package=stream_alert.athena_partition_refresh \
--cover-package=stream_alert.rule_processor \
--cover-package=stream_alert.shared \
--cover-package=stream_alert.threat_intel_downloader \
--cover-package=stream_alert_cli \
--cover-min-percentage=80 \
--cover-html \
--cover-html-dir=htmlcov \
--with-timer \
--timer-top-n=10
