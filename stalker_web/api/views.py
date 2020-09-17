import json
from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from elasticsearch import Elasticsearch, helpers


def sendJSON(success, msg=None):
	data = {}
	data['success'] = success
	if msg:
		data['msg'] = msg

	return JsonResponse(data)


def get_client_ip(request):
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_forwarded_for:
		ip = x_forwarded_for.split(',')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	return ip


def esConnect():
	return Elasticsearch([settings.ES_HOST])


@csrf_exempt
def register_host(request):
	cur = connection.cursor()
	req = json.loads(request.body.decode('utf-8'))
	guid = req['guid']
	ip = get_client_ip(request)
	cur.execute("""INSERT INTO hosts (guid, ip) VALUES (%s, %s)""", (guid, ip))	
	connection.commit()
	return sendJSON(True)


@csrf_exempt
def add_events(request):
	es = esConnect()
	req = json.loads(request.body.decode('utf-8'))

	ip = get_client_ip(request)
	# update host table with ip
	# check for sysmon version/configuration hash

	#cur.execute("""SELECT id FROM hosts WHERE guid=%s""", (req['host_guid'],))	
	#host_id = cur.fetchone()[0]

	#event['HostId'] = 1
	# maybe use generator on bulk call to add HostID to each event
	response = helpers.bulk(es, req['events'], index='stalker', chunk_size=2000)

	return sendJSON(True)

