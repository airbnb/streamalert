#!/usr/bin/env python2.7

# DemistoClient
# Python client that shows how to invoke API calls on the Demisto server.
# To use the client, you should generate an API key under Settings->Integrations->API Keys
#
# Author:       Lior
# Version:      1.1
#
from requests import Session
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)


class DemistoClient:
    XSRF_TOKEN_KEY = "X-XSRF-TOKEN"
    XSRF_COOKIE_KEY = "XSRF-TOKEN"
    AUTHORIZATION = "Authorization"

    # New client that does not do anything yet
    def __init__(self, apiKey, server, username=None, password=None):
        if not ((apiKey or (username and password)) and server):
            raise ValueError(
                "You must provide server argument and key or user & password")
        if not server.find('https://') == 0 and not server.find('http://') == 0:
            raise ValueError(
                "Server must be a url (e.g. 'https://<server>' or 'http://<server>')")
        if not server[-1] == '/':
            server += '/'

        self.server = server
        self.session = Session()
        if not apiKey:
            self.xsrf = True
            try:
                r = self.session.get(server, verify=False)
            except InsecureRequestWarning:
                pass
            self.token = r.cookies[DemistoClient.XSRF_COOKIE_KEY]
            self.username = username
            self.password = password
        else:
            self.xsrf = False
            self.apiKey = apiKey

    def req(self, method, path, data):
        h = {"Accept": "application/json",
             "Content-type": "application/json"}

        if self.xsrf:
            h[DemistoClient.XSRF_TOKEN_KEY] = self.token
        else:
            h[DemistoClient.AUTHORIZATION] = self.apiKey
        try:
            if self.session:
                r = self.session.request(
                    method, self.server+path, headers=h, verify=False, json=data)
            else:
                raise RuntimeError("Session not initialized!")
        except InsecureRequestWarning:
            pass
        return r

    def Login(self):
        data = {'user': self.username, 'password': self.password}
        return self.req("POST", "login", data)

    def Logout(self):
        return self.req("POST", "logout", {})

    def CreateIncident(self, inc_name, inc_type, inc_severity, inc_owner, inc_labels, inc_details, custom_fields, createInvestigation=True, **kwargs):
        data = {"type": inc_type,
                "name": inc_name,
                "owner": inc_owner,
                "severity": inc_severity,
                "labels": inc_labels,
                "customFields": custom_fields,
                "details": inc_details}

        if createInvestigation is True:
            data['createInvestigation'] = True

        for e in kwargs:
            if e not in data:
                data[e] = kwargs[e]

        return self.req("POST", "incident", data)

    def SearchIncidents(self, page, size, query):
        data = {'filter': {'page': page, 'size': size,
                           'query': query, 'sort': [{'field': 'id', 'asc': False}]}}
        r = self.req("POST", "incidents/search", data)
        if r.status_code != 200:
            raise RuntimeError(
                'Error searching incidents - %d (%s)' % (r.status_code, r.reason))
        return r.json()

    def SearchAutomation(self, query):
        data = {'query': query}
        r = self.req("POST", "automation/search", data)
        r.raise_for_status()
        rj = r.json()
        if "scripts" not in rj:
            raise RuntimeError("Error searching automations - scripts attribute is not found in response")
        return rj

    def LoadAutomation(self, automation_id):
        data = {}
        r = self.req("POST", "automation/load/{}".format(automation_id), data)
        r.raise_for_status()
        return r.json()

    def SaveAutomation(self, script, query=None, save_password=False):
        if query is None:
            """
            if query is empty string(""), /automation will return all automations server currently have(huge!).
            to avoid it, script name is set as default. then only saved automation will be returned.
            """
            query = "name:{}".format(script["name"])
        data = {
            'filter': {"query": query},
            'script': script,
            'savePassword': save_password
        }
        r = self.req("POST", "automation", data)
        r.raise_for_status()
        return r.json()

    def DeleteAutomation(self, script, query=None):
        if query is None:
            """
            unlike /automation, /automation/delete does not return any automations even if query is empty string("").
            so the default is "".
            """
            query = ""
        data = {
            'filter': {"query": query},
            'script': script
        }
        r = self.req("POST", "automation/delete", data)
        r.raise_for_status()
        return r.json()

    def UpdateAutomation(self, target_id, target_name, **automation):
        """
        update automation based on target_id or target_name.
        either target_id or target_name must be required, another should be None.
        if both is specified(not None), target_id will be used.
        """
        automations = None
        if target_id is not None:
            automations = self.SearchAutomation("id:{}".format(target_id))
            if "id" not in automation:
                automation["id"] = target_id
            elif automation["id"] != target_id:
                raise RuntimeError("Error updating automations - id specified in automation. id can't be updated.")
        elif target_name is not None:
            automations = self.SearchAutomation("name:{}".format(target_name))
            if "name" not in automation:
                automation["name"] = target_name
        else:
            raise RuntimeError("target_id or target_name must be required.")
        if len(automations["scripts"]) == 0:
            automation["name"] = target_name
            if "id" in automation:
                # id should be generated by demisto
                del automation["id"]
        elif len(automations["scripts"]) == 1:
            current_automation = automations["scripts"][0]
            for (key, value) in current_automation.items():
                if key not in automation:
                    automation[key] = value
        else:
            raise RuntimeError("name search returns multiple({}) automations?? impossible.".format(len(automations)))
        return self.SaveAutomation(automation)
