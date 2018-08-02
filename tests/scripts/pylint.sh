#! /bin/bash
echo 'Starting pylint script'
pylint *.py helpers matchers rules stream_alert stream_alert_cli tests
