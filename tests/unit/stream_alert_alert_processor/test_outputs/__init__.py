'''
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
from stream_alert.alert_processor.main import _load_output_config

REGION = 'us-east-1'
FUNCTION_NAME = 'corp-prefix_prod_streamalert_alert_processor'
CONFIG = _load_output_config('tests/unit/conf/outputs.json')
KMS_ALIAS = 'alias/stream_alert_secrets_test'
