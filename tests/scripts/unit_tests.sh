#!/bin/bash

# Export fake creds to keep moto from complaining
export AWS_ACCESS_KEY_ID=foobar_key
export AWS_SECRET_ACCESS_KEY=foobar_secret
export AWS_SESSION_TOKEN=foobar_session_token
export AWS_DEFAULT_REGION=us-east-1

# Run unit tests with pytest and coverage and timer
pytest --cov --durations=10 tests/unit
