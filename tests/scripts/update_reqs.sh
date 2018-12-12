#! /bin/bash
pip install -r requirements-top-level.txt --upgrade --force-reinstall
pip freeze -r requirements-top-level.txt > requirements.txt

echo "Please also update library versions in stream_alert_cli/manage_lambda/package.py"
