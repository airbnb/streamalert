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
from fnmatch import fnmatch
import logging
import logging.handlers


class SuppressNonErrors(logging.Filter):
    """Simple logging filter to allow only caching error messages to a MemoryHandler"""
    def filter(self, record):
        return record.levelno == logging.ERROR


class SuppressNoise(logging.Filter):
    """Simple logging filter for suppressing specific log messages that we
    do not want to print during testing. Add any suppressions to the tuple.
    """

    def filter(self, record):
        suppressed_messages = (
            'Starting download from S3*',
            'Completed download in*',
            '*triggered an alert on log type*',
            '*Firehose*',
            'Got * normalized records'
        )

        message = record.getMessage()

        return (
            not any(fnmatch(message, suppression) for suppression in suppressed_messages)
        )


LOGGER_SA = logging.getLogger('StreamAlert')
LOGGER_SA.setLevel(logging.INFO)

LOGGER_SO = logging.getLogger('StreamAlertOutput')
LOGGER_SO.setLevel(logging.INFO)

LOGGER_SH = logging.getLogger('StreamAlertShared')
LOGGER_SH.setLevel(logging.INFO)

logging.basicConfig(format='%(name)s [%(levelname)s]: %(message)s')
LOGGER_CLI = logging.getLogger('StreamAlertCLI')
LOGGER_CLI.setLevel(logging.INFO)

# silence imported loggers
for logger in logging.Logger.manager.loggerDict:
    if logger.startswith('StreamAlert'):
        continue
    logging.getLogger(logger).setLevel(logging.CRITICAL)

def get_log_memory_hanlder():
    """Get a logging MemoryHandler with a default buffer size of 1000
    We don't care about assigning a target to this handler since these logs
    will not actually be written out to disk, etc

    Returns:
        logging.handlers.MemoryHandler: In memory logging handler that caches
            all messages going through the root logger to a buffer
    """
    log_mem_hanlder = logging.handlers.MemoryHandler(1000)

    # Add a filter to suppress everything that is not an error
    log_mem_hanlder.addFilter(SuppressNonErrors())

    # Add the MemoryHandler to the root logger to capture all logs in all loggers
    logging.getLogger().addHandler(log_mem_hanlder)

    return log_mem_hanlder
