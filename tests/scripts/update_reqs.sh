#! /bin/bash
pip install -r requirements-top-level.txt --upgrade
pip freeze -r requirements-top-level.txt > requirements.txt