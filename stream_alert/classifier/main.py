"""
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
"""
  # Suppresses RuntimeWarning import error in Lambda

import json

from stream_alert.classifier import Classifier
from stream_alert.shared import logger


def handler(event, _):
    """Main Lambda handler function"""
    try:
        Classifier().run(event.get('Records', []))
    except Exception:
        logger.get_logger(__name__).exception('Invocation event: %s', json.dumps(event))
        raise
