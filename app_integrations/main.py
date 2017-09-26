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
from app_integrations.config import AppConfig
from app_integrations.apps.app_base import get_app


def handler(event, context):
    """Main lambda handler use as the entry point

    Args:
        event (dict): Always empty (for now) event object
        context (LambdaContxt): AWS LambdaContext object
    """
    if event and 'full_run' in event:
        # TODO: implement support for historical runs via input events
        pass

    try:
        # Load the config from this context object, pulling info from parameter store
        config = AppConfig.load_config(context)

        # The config specifies what app this function is supposed to run
        app = get_app(config)

        # Run the gather operation
        app.gather()
    except:
        raise
    finally:
        # If the config was loaded, save a bad state if the current state is not
        # marked as a success (aka running)
        if 'config' in locals():
            if not config.is_success:
                config.mark_failure()
