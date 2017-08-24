#! /bin/bash
find . -name '*.py' -not -path './docs/source/*' -not -path './venv/*' -exec pylint '{}' +