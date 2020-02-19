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

import json

from streamalert.rules_engine import RulesEngine
from streamalert.shared import logger


def handler(event, _):
    """Main Lambda handler function"""
    try:
        records = []
        for record in event.get('Records', []):
            body = json.loads(record['body'])
            if isinstance(body, list):
                records.extend(body)
            else:
                records.append(body)
        RulesEngine().run(records)
    except Exception:
        logger.get_logger(__name__).exception('Invocation event: %s', json.dumps(event))
        raise
