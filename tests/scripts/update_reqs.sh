#! /bin/bash
pip install -r requirements-top-level.txt --upgrade --force-reinstall --no-cache-dir
pip freeze -r requirements-top-level.txt > requirements.txt

echo "Please also update library versions in streamalert_cli/manage_lambda/package.py"
