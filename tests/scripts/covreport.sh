#! /bin/bash
if [ -f ".coverage" ]; then
  echo "Removing previous coverage file"
  rm .coverage
fi

if [ -d "htmlcov" ]; then
  echo "Removing previously generated html coverage folder"
  rm -rf htmlcov
fi

tests/scripts/unit_tests.sh
coverage html
open htmlcov/index.html
