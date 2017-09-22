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

class ThreatIntel(object):
    """Load intelligence from csv gz files into a dictionary."""

    def __init__(self, intel_dir, delimiter=','):
        """Initialize class instance variables
        Args:
            intel_dir (str): Location where stores compressed intelligence files

        Instance variables:
            self._intel_dict (dict): A dictionary to store all intelligence read
                from *.csv.gz files
            self._intel_dir (str):  Location where stores compressed intelligence
                files
        """
        self._intel_dict = dict()
        self._intel_dir = intel_dir
        self._delimiter = delimiter

    def read_compressed_files(self):
        """Read all intelligence from csv.gz files located in threat_intel
        directory into a dictionary. csv filename should follow the convention
        that <ioc_type>.csv.gz. The basename (without extension) of csv file
        will be the key in return dictionary.

        Returns:
            (dict): A dictionary stores intelligence in format
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
                        "deadbeefdeadbeef": ["mal_md5", "soure_bar"]
                    }
                }
            None: if location storing intelligence is not existed
        """
        if not os.path.exists(self._intel_dir):
            return

        gz_files = [os.path.join(self._intel_dir, gz_file)
                    for gz_file in os.listdir(self._intel_dir)
                    if gz_file.endswith('.gz')]

        for gz_file in gz_files:
            with gzip.open(gz_file, 'rb') as f:
                csv_reader = csv.reader(f, delimiter=self._delimiter)
                ioc_type = os.path.basename(gz_file).split('.')[0]
                if ioc_type not in self._intel_dict:
                    self._intel_dict[ioc_type] = dict()
                for row in csv_reader:
                    if len(row) < 2:
                        LOGGER.debug('Warming, each row in CSV file should \
                            contain at least two fields. Bad row [%s]',
                                     row)
                        continue
                    self._intel_dict[ioc_type][row[0]] = row[1:]

        return self._intel_dict
