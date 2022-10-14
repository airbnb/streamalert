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


Classes related to dependency injection container.
"""


class ServiceContainer:
    """A container that houses all configurations and services for the application runtime.

    @see https://symfony.com/doc/current/service_container.html
    """
    def __init__(self, parameters):
        self._services = {}
        self._parameters = parameters
        self._definitions = {}

    def get(self, service_id):
        """Returns a service

        All instances of a unique service id are singleton.
        """
        if service_id not in self._services:
            self._services[service_id] = self._instantiate(service_id)
        return self._services[service_id]

    def get_parameter(self, parameter_name):
        """Returns a parameter registered in the service container"""
        if parameter_name not in self._parameters:
            raise ValueError(f'ServiceContainer no such parameter: "{parameter_name}"')

        return self._parameters[parameter_name]

    @property
    def parameters(self):
        return self._parameters

    def register(self, definition):
        """

        Params:
            definition (ServiceDefinition):
        """
        service_id = definition.service_id
        if service_id in self._definitions:
            raise ValueError(f'ServiceContainer registering duplicate definition: "{service_id}"')

        self._definitions[service_id] = definition

    def _instantiate(self, service_id):
        if service_id in self._definitions:
            return self._definitions[service_id].instantiate(self)

        raise ValueError(f'ServiceContainer does not know how to create: "{service_id}"')


class ServiceDefinition:
    def __init__(self, service_id, definition):
        self._service_id = service_id
        self._definition = definition

    @property
    def service_id(self):
        return self._service_id

    def instantiate(self, service_container):
        return self._definition(service_container)
