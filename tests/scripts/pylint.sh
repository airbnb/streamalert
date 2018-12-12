#! /bin/bash
echo 'Starting pylint script'
pylint *.py rules stream_alert stream_alert_cli tests
