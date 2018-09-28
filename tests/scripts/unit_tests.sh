#!/bin/bash
nosetests tests/unit \
--with-coverage \
--cover-package=stream_alert \
--cover-package=stream_alert_cli \
--cover-min-percentage=80 \
--cover-html \
--cover-html-dir=htmlcov \
--with-timer \
--timer-top-n=10
