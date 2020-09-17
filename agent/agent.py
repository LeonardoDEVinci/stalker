#Sysmon.exe -i -h md5,sha1,sha256,imphash -l -n -accepteula

import json
import winreg
import requests
from winevt import EventLog
import xml.etree.ElementTree as ET


REG_KEY = 'SOFTWARE\\Stalker'
#SINGLE_TAGS = ['Version']
SYSTEM_TAGS = ['EventID', 'Computer']
EVENT_TYPES = {
    '1': 'ProcessCreate',
    '2': 'FileCreateTime',
    '3': 'NetworkConnect',
    '4': 'StateChange',
    '5': 'ProcessTerminate',
    '6': 'DriverLoad',
    '7': 'ImageLoad',
    '8': 'CreateRemoteThread',
    '9': 'RawAccessRead',
    '10': 'ProcessAccess',
    '11': 'FileCreate',
    '12': 'RegistryEvent',
    '13': 'RegistryEvent',
    '14': 'RegistryEvent',
    '15': 'FileCreateStreamHash',
    '16': 'ConfigurationChange',
    '17': 'PipeEvent',
    '18': 'PipeEvent',
    '19': 'WmiEvent',
    '20': 'WmiEvent',
    '21': 'WmiEvent',
    '22': 'DNSQuery',
    '23': 'FileDelete'
}
#EVENTDATA_TAGS = ['CommandLine', 'Company', 'CreationUtcTime', 'CurrentDirectory', 'Description', 'DestinationHostname', 'DestinationIp', 'DestinationIsIpv6', 'DestinationPort', 'DestinationPortName', 'FileVersion', 'Image', 'ImageLoaded', 'Initiated', 'IntegrityLevel', 'LogonId', 'OriginalFileName', 'ParentCommandLine', 'ParentImage', 'ParentProcessId', 'PreviousCreationUtcTime', 'ProcessId', 'Product', 'Protocol', 'Signature', 'SignatureStatus', 'Signed', 'SourceHostname', 'SourceIp', 'SourceIsIpv6', 'SourcePort', 'SourcePortName', 'State', 'TargetFilename', 'TerminalSessionId', 'User', 'UtcTime']
INT_TAGS = ['DestinationPort', 'ParentProcessId', 'ProcessId', 'SourcePort']
UUID_TAGS = ['LogonGuid', 'ParentProcessGuid', 'ProcessGuid']
HASH_TAGS = [
    'Hashes',
    'ConfigurationFileHash'
]


def registerHost():
    # HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
    # maybe get guid from server instead?
    #server = input("Enter server URL: ")
    server = 'http://127.0.0.1:8000'
    config = {}
    config['guid'] = '19ff5e27-7b54-488d-b952-ded8f2d3ef4d'
    r = requests.post(server + '/api/register_host', json=config)
    print(r.json())


def getConfig():
    config = {}
    config['event_record_id'] = 1
    config['server'] = 'http://127.0.0.1:8000'
    return config


def fixHashes(text):
    hashes = {}

    if text:
        for hash in text.split(','):
            type, value = hash.split('=')
            hashes[type.upper()] = value
        
    return hashes


def sendEvents(config, events):
    r = requests.post(config['server'] + '/api/add_events', json=events)
    print(r.json())


def queryEvents(config):
    query = EventLog.Query("Microsoft-Windows-Sysmon/Operational", "Event/System[EventRecordID>%s]" % config['event_record_id'])

    events = {}
    events['events'] = []

    for count, event in enumerate(query, 1):
        event_dict = {}
        root = ET.fromstring(event.xml)
        
        # Get system elements
        for child in root[0]:    #0 - system
            tag = child.tag.split('}')[1]

            if tag in SYSTEM_TAGS:
                if tag == 'EventID':
                    event_dict['EventType'] = EVENT_TYPES.get(child.text)
                    event_dict[tag] = int(child.text)
                else:
                    event_dict[tag] = child.text

        # Get eventdata elements
        for child in root[1]:    #1 - eventdata
            name = child.attrib['Name']
            if name in UUID_TAGS:
                event_dict[name] = child.text[1:-1]
            elif name in HASH_TAGS:
                for k, v in fixHashes(child.text).items():
                    if name != 'ConfigurationFileHash':
                        event_dict[k] = v
                    else:
                        events[name] = v
            else:
                if name in INT_TAGS:
                    event_dict[name] = int(child.text)
                else:
                    event_dict[name] = child.text

        events['events'].append(event_dict)

        if count % 5000 == 0:
            sendEvents(config, events)
            events['events'] = []            

    if not events['events']:
        sendEvents(config, events)


if __name__ == '__main__':
    #registerHost()
    config = getConfig()
    events = queryEvents(config)
