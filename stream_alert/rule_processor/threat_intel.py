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
import csv
import gzip
import os

from stream_alert.rule_processor import LOGGER

class StreamThreatIntel(object):
    """Load intelligence from csv.gz files into a dictionary."""

    __intelligence = {}
    __config = {}

    @classmethod
    def read_compressed_files(cls, intel_dir, delimiter=','):
        """Read intelligence into memory

        Read all intelligence from csv.gz files located in threat_intel
        directory into a dictionary. CSV filename should follow the convention
        <ioc_type_as_basename>.csv.gz. The basename (without extension) of csv
        file will be the key in return dictionary.

        Returns:
            (dict): Threat intelligence in the following format:
                {
                    "domain": {
                        "evil1.com": ["apt_domain", "source1 reported evil1.com"],
                        "evil2.com": ["c2_domain", "source2 reported evil2.com"]
                    },
                    "ip": {
                        "1.1.1.2": ["scan_ip", "source reported ip1"],
                        "2.2.2.2": ["scan_ip", "source reported ip2"]
                    },
                    "url": {
                        "www.hacker.com/evil_page": ["mal_url", "source_foo"]
                    },
                    "md5": {
                        "0123456789abcdef0123456789abcdef": ["mal_md5", "source_bar"]
                    }
                }
            None: if the intelligence directory does not exist
        """
        if not os.path.exists(intel_dir):
            return

        gz_files = [os.path.join(intel_dir, gz_file) for gz_file
                    in os.listdir(intel_dir)
                    if gz_file.endswith('.gz')]

        for gz_file in gz_files:
            with gzip.open(gz_file, 'r') as ioc_file:
                csv_reader = csv.reader(ioc_file, delimiter=delimiter)
                ioc_type = os.path.basename(gz_file).split('.')[0]
                if ioc_type not in cls.__intelligence:
                    cls.__intelligence[ioc_type] = dict()
                for row in csv_reader:
                    if len(row) < 2:
                        LOGGER.debug('Warning, each row in CSV file should '
                                     'contain at least two fields. Bad row [%s]',
                                     row)
                        continue
                    cls.__intelligence[ioc_type][row[0]] = row[1:]

        return cls.__intelligence

    @classmethod
    def load_intelligence(cls, config, intel_dir='threat_intel'):
        """Load intelligence from csv.gz files into a dictionary

        Args:
            intel_dir (str): Location where stores compressed intelligence
        """
        if cls.__intelligence:
            return
        if (config.get('threat_intel')
                and config['threat_intel'].get('enabled')
                and config['threat_intel'].get('mapping')):
            cls.__intelligence = cls.read_compressed_files(intel_dir)
            cls.__config = config['threat_intel'].get('mapping')

    @classmethod
    def get_intelligence(cls):
        return cls.__intelligence

    @classmethod
    def get_config(cls):
        return cls.__config
