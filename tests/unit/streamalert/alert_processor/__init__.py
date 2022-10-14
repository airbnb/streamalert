"""
Copyright 2017-present Airbnb, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from streamalert.shared import resources
from streamalert.shared.config import load_config

REGION = 'us-east-1'
ACCOUNT_ID = '123456789012'
PREFIX = 'prefix'
FUNCTION_NAME = f'{PREFIX}_streamalert_alert_processor'

base_config = load_config('tests/unit/conf/', include={'outputs.json'})['outputs']
CONFIG = resources.merge_required_outputs(base_config, PREFIX)

ALERTS_TABLE = f'{PREFIX}_streamalert_alerts'
KMS_ALIAS = 'alias/streamalert_secrets_test'

MOCK_ENV = {
    'AWS_ACCOUNT_ID': ACCOUNT_ID,
    'STREAMALERT_PREFIX': PREFIX,
    'AWS_DEFAULT_REGION': REGION
}
