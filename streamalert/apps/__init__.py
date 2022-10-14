"""Initialize logging for the app."""
import importlib
import logging
import os

from streamalert.apps.exceptions import AppException


class StreamAlertApp:
    """Class to be used as a decorator to register all AppIntegration subclasses"""
    _apps = {}

    def __new__(cls, app):
        StreamAlertApp._apps[app.type()] = app
        return app

    @classmethod
    def get_app(cls, app_type):
        """Return the proper app integration class for this service

        Args:
            config (AppConfig): Loaded configuration with service, etc
            init (bool): Whether or not this class should be instantiated with
                the config that has been passed in

        Returns:
            AppIntegration: Subclass of AppIntegration corresponding to the config

        Raises:
            AppException: Error is raised if the requested app does not exist
        """
        try:
            return cls._apps[app_type]
        except KeyError as e:
            raise AppException(f'App integration does not exist for type: {app_type}') from e

    @classmethod
    def get_all_apps(cls):
        """Return a copy of the cache containing all of the app subclasses

        Returns:
            dict: Cached dictionary of all registered StreamAlertApps where
                the key is the app type and the value is the class object
        """
        return cls._apps.copy()


# Import all files containing subclasses of AppIntegration, skipping the common base class
for app_file in os.listdir(os.path.join(os.path.dirname(__file__), '_apps')):
    # Skip the common base file and any non-py files
    if app_file.startswith('__init__') or not app_file.endswith('.py'):
        continue

    full_import = ['streamalert', 'apps', '_apps', os.path.splitext(app_file)[0]]

    importlib.import_module('.'.join(full_import))
