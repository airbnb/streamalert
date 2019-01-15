This directory was directly copied from https://github.com/demisto/demisto-py, as it is not
on PyPi and cannot be installed as a dependency via pip or any other package manager.

Included is a copy of the license, the readme, and the relevant code.


----

# Demisto SDK for Python

A Python library for the Demisto API.

## Usage

First, get Demisto api-key. You can generate one via Demisto client - on `settings`->`API keys`.

Create demisto client instance with the api-key and server-url:
```python
import demisto

client = demisto.DemistoClient('<your-api-key-goes-here>', 'https://localhost:8443')

```

Alternatively, you can login with username and password:

```python
import demisto

client = demisto.DemistoClient('', 'https://localhost:8443', '<username>', '<password>')
client.Login() # Should return <Response [200]>

```


You can create incidents:

```python
client.CreateIncident('incident-name', 'incident-type', 0, 'owner', [{"type": "label", "value": "demisto"}], 'details', {"alertsource":"demisto"})

```

By setting the parameter "createInvestigation" to **True**, the newly created incident will also create an Investigation. This will allow for Playbooks to be triggered automatically for the newly created Incident.

```python
client.CreateIncident('incident-name', 'incident-type', 0, 'owner', [{"type": "label", "value": "demisto"}], 'details', {"alertsource":"demisto"}, createInvestigation=True)

```

You can search for incidents by filter:

```python
client.SearchIncidents(0,100,'')
```

Will return all incidents, with a max limit of 100 incidents to return, and page 0 of it

A bit more complex search:

```python
client.SearchIncidents(0,100,'name:test')
```

Will return incidents with name test

* Note - on macOS, the system OpenSSL does not supprot TLSv12 which Demisto server mandates. To run the examples on macOS you will need to install brew and then OpenSSL and Python via brew.

If you don't have brew installed:
```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

To install Python with new OpenSSL support:
```
brew update
brew install openssl
brew install python --with-brewed-openssl
```

To run the examples:
```
/usr/local/Cellar/python/2.7.13/bin/python example -param val -param val
```
