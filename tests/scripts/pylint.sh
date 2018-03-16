#! /bin/bash
echo 'Starting pylint script'
pylint *.py app_integrations helpers matchers rules stream_alert stream_alert_cli tests
