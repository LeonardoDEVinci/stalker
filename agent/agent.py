#Sysmon.exe -i -h md5,sha1,sha256,imphash -l -n -accepteula

import json
import winreg
import ctypes
import requests
import argparse
from winevt import EventLog
import xml.etree.ElementTree as ET


REG_PATH = 'SOFTWARE\\Stalker'
REG_EVENT_ID_KEY = 'EventRecordID'
REG_SERVER_KEY = 'Server'

#SINGLE_TAGS = ['Version']
SYSTEM_TAGS = ['EventRecordID', 'EventID', 'Computer']
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


def installAgent(server_url, zero):
	# test connection
	try:
		r = requests.get(server_url + '/api/test', timeout=30)
	except:
		print('Could not connect to server.')
		return

	if zero:
		event_record_id = 0
	else:
		query = EventLog.Query("Microsoft-Windows-Sysmon/Operational", "Event/System")
		*_, event = query
		event_dict = eventToDict(event)
		event_record_id = event_dict['EventRecordID']

	# write server and last event id to registry
	winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
	with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_WRITE) as reg_key:
		winreg.SetValueEx(reg_key, REG_EVENT_ID_KEY, 0, winreg.REG_QWORD, event_record_id)
		winreg.SetValueEx(reg_key, REG_SERVER_KEY, 0, winreg.REG_SZ, server_url)


def getConfig():
	config = {}

	with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ) as reg_key:
		config['EventRecordID'], regtype = winreg.QueryValueEx(reg_key, REG_EVENT_ID_KEY)
		config['Server'], regtype = winreg.QueryValueEx(reg_key, REG_SERVER_KEY)

	return config


def fixHashes(text):
	# split the hashes into their own fields
	hashes = {}

	if text:
		for hash in text.split(','):
			hash_type, value = hash.split('=')
			hashes[hash_type.upper()] = value
		
	return hashes


def sendEvents(config, events):
	# send events to server
	r = requests.post(config['Server'] + '/api/add_events', json=events, timeout=30)
	print(r.json())


def eventToDict(event):
	event_dict = {}
	root = ET.fromstring(event.xml)
		
	# Get system elements
	for child in root[0]:	 #0 - system
		tag = child.tag.split('}')[1]

		if tag in SYSTEM_TAGS:
			if tag == 'EventID':
				event_dict['EventType'] = EVENT_TYPES.get(child.text)
				event_dict[tag] = int(child.text)
			elif tag == 'EventRecordID':
				event_dict[tag] = int(child.text)
			else:
				event_dict[tag] = child.text

	# Get eventdata elements
	for child in root[1]:	 #1 - eventdata
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

	return event_dict


def queryEvents(config):
	# query events from events log
	query = EventLog.Query("Microsoft-Windows-Sysmon/Operational", "Event/System")

	events = {}
	events['events'] = []

	for count, event in enumerate(query, 1):
		event_dict = eventToDict(event)
		if event_dict['EventRecordID'] < config['EventRecordID']:
			continue

		events['events'].append(event_dict)

		if count % 5000 == 0:
			sendEvents(config, events)
			events['events'] = []

	if events['events']:
		sendEvents(config, events)

	if event_dict:
		with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_WRITE) as reg_key:
			winreg.SetValueEx(reg_key, REG_EVENT_ID_KEY, 0, winreg.REG_QWORD, event_dict['EventRecordID'])



if __name__ == '__main__':
	admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
	if not admin:
		print('Must be run as admin.')
		exit()

	parser = argparse.ArgumentParser(description='Stalker')
	parser.add_argument('-i', dest='install', action='store_true', help='Install the agent')
	parser.add_argument('-z', dest='zero', action='store_true', default=False, help='Start from the first EventRecord ID (default: False)')
	parser.add_argument('-s', dest='server_url', help='Stalker Server URL')
	parser.add_argument('-u', dest='uninstall', help='Uninstall the agent')
	args = parser.parse_args()
	#parser.print_help()

	if args.install:
		if not args.server_url:
			parser.error("-s SERVER_URL is required with -i")
		else:
			installAgent(args.server_url, args.zero)
	else:
		config = getConfig()
		events = queryEvents(config)

