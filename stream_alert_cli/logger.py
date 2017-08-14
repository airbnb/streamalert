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

import logging

LOGGER_SA = logging.getLogger('StreamAlert')
LOGGER_SA.setLevel(logging.INFO)

LOGGER_SO = logging.getLogger('StreamAlertOutput')
LOGGER_SO.setLevel(logging.INFO)

logging.basicConfig(format='%(name)s [%(levelname)s] (%(module)s.%(funcName)s): %(message)s')
LOGGER_CLI = logging.getLogger('StreamAlertCLI')
LOGGER_CLI.setLevel(logging.INFO)

# silence imported loggers
for logger in logging.Logger.manager.loggerDict:
    if logger.startswith('StreamAlert'):
        continue
    logging.getLogger(logger).setLevel(logging.CRITICAL)
