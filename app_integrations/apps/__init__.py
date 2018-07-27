"""Create some package level items to make this nicer to use"""
import importlib
import os

from app_integrations.exceptions import AppException


class StreamAlertApp(object):
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
        """
        try:
            return cls._apps[app_type]
        except KeyError:
            raise AppException('App integration does not exist for type: {}'.format(app_type))

    @classmethod
    def get_all_apps(cls):
        """Return a copy of the cache containing all of the app subclasses

        Returns:
            dict: Cached dictionary of all registered StreamAlertApps where
                the key is the app type and the value is the class object
        """
        return cls._apps.copy()


# Import all files containing subclasses of AppIntegration, skipping the common base class
for app_file in os.listdir(os.path.dirname(__file__)):
    # Skip the common base file and any non-py files
    if app_file.startswith(('__init__', 'app_base')) or not app_file.endswith('.py'):
        continue

    full_import = ['app_integrations', 'apps', os.path.splitext(app_file)[0]]

    importlib.import_module('.'.join(full_import))
