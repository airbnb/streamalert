#! /bin/bash
nosetests test/unit --with-coverage --cover-package=stream_alert.rule_processor --cover-package=stream_alert.alert_processor --cover-package=stream_alert_cli --cover-min-percentage=80