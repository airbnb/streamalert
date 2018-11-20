#! /bin/bash
AWS_ACCESS_KEY_ID=test_key \
AWS_SECRET_ACCESS_KEY=test_secret \
./manage.py lambda test --processor rule
