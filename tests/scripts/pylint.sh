#! /bin/bash
echo 'Starting pylint script'
pylint *.py rules streamalert streamalert_cli tests
