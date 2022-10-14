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
from unittest.mock import MagicMock

from streamalert.scheduled_queries.command.processor import CommandProcessor


class TestCommandProcessor:
    def __init__(self):
        self._processor = None
        self._logger = None
        self._kinesis = None
        self._state_manager = None
        self._manager = None

    def setup(self):
        self._logger = MagicMock(name='MockLogger')
        self._kinesis = MagicMock(name='MockKinesis')
        self._state_manager = MagicMock(name='MockStateManager')
        self._manager = MagicMock(name='MockManagerFactory')

        manager_factory = MagicMock()
        manager_factory.new_manager.return_value = self._manager

        self._processor = CommandProcessor(
            logger=self._logger,
            kinesis=self._kinesis,
            state_manager=self._state_manager,
            manager_factory=manager_factory
        )

    def test_nonblocking_single_pass_not_finished(self):
        """StreamQuery - CommandProcessor - nonblocking_single_pass - Not Finished"""
        self._manager.finished_query_packs = []
        self._manager.num_registered_queries = 1

        result = self._processor.nonblocking_single_pass()

        assert not result

    def test_nonblocking_single_pass_finished_succeeded(self):
        """StreamQuery - CommandProcessor - nonblocking_single_pass - Finished"""
        query_pack = MagicMock(name='MockQueryPack')
        query_pack.query_execution_id = '1111-2222'
        query_pack.query_execution.is_succeeded.return_value = True
        self._manager.finished_query_packs = [
            query_pack
        ]
        self._manager.num_registered_queries = 1
        self._state_manager.get.return_value = {
            'sent_to_streamalert': False
        }

        result = self._processor.nonblocking_single_pass()

        assert result
        self._kinesis.send_query_results.assert_called_with(query_pack)

    def test_nonblocking_single_pass_finished_failed(self):
        """StreamQuery - CommandProcessor - nonblocking_single_pass - Failed"""
        query_pack = MagicMock(name='MockQueryPack')
        query_pack.query_execution_id = '1111-2222'
        query_pack.query_execution.is_succeeded.return_value = False
        self._manager.finished_query_packs = [
            query_pack
        ]
        self._manager.num_registered_queries = 1
        self._state_manager.get.return_value = {
            'sent_to_streamalert': False
        }

        result = self._processor.nonblocking_single_pass()

        assert result
        self._kinesis.send_query_results.assert_not_called()

    # pylint: disable=invalid-name
    def test_nonblocking_single_pass_finished_succeeded_already_sent(self):
        """StreamQuery - CommandProcessor - nonblocking_single_pass - Failed"""
        query_pack = MagicMock(name='MockQueryPack')
        query_pack.query_execution_id = '1111-2222'
        query_pack.query_execution.is_succeeded.return_value = True
        self._manager.finished_query_packs = [
            query_pack
        ]
        self._manager.num_registered_queries = 1
        self._state_manager.get.return_value = {
            'sent_to_streamalert': True
        }

        result = self._processor.nonblocking_single_pass()

        assert result
        self._kinesis.send_query_results.assert_not_called()
