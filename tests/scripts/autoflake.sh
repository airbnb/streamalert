#! /bin/bash
autoflake --recursive --in-place --remove-all-unused-imports $1
