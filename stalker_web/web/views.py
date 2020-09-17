import json
from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from elasticsearch import Elasticsearch, helpers


def esConnect():
	return Elasticsearch([settings.ES_HOST])


def createMapping(request):
	es = esConnect()
	index_settings = {
		"settings": {
			"number_of_shards": 2
		},
		"mappings": {
			"properties": {
				"CreationUtcTime": {
					"type": "date",
					"format": "yyyy-MM-dd HH:mm:ss.SSS"
				},
				"PreviousCreationUtcTime": {
					"type": "date",
					"format": "yyyy-MM-dd HH:mm:ss.SSS"
				},
				"UtcTime": {
					"type": "date",
					"format": "yyyy-MM-dd HH:mm:ss.SSS"
				},
				"DestinationIp": {
					"type": "ip"
				},
				"SourceIp": {
					"type": "ip"
				}
			}
		}
	}
	response = es.indices.create(index=settings.ES_INDEX, body=index_settings)
	return HttpResponse(response)


def pagination(page, hits_count, size):
	pages = []

	return pages


def getProcCreate(guid):
	es = esConnect()
	body = {
		"query": {
			"bool": {
				"must": [
					{"term": {"ProcessGuid.keyword": guid} },
					{"term": {"EventID": 1} }
				]
			}
		}
	}

	res = es.search(index=settings.ES_INDEX, body=body)
	hits = res['hits']['hits']
	if hits:
		return hits[0]['_source']
	else:
		return None


def getChildren(guids):
	es = esConnect()
	body = {
		"size": 25,
		"sort": [
			{
				"ParentProcessGuid.keyword": "asc",
				"UtcTime": "asc"
			}
		],
		"query": {
			"bool": {
				"must": [
					{"terms": {"ParentProcessGuid.keyword": guids} },
					{"term": {"EventID": 1} }
				]
			}
		}
	}

	res = es.search(index=settings.ES_INDEX, body=body)
	events = []

	for hit in res['hits']['hits']:
		events.append(hit['_source'])

	return events


def processTree(guid):
	procs = []
	main_proc = getProcCreate(guid)
	if not main_proc:
		return procs
		
	procs.append(main_proc)
	events = getChildren([guid]) 

	while events:
		children = []
		child_guids = []
		parent_guid = events[0]['ParentProcessGuid']
		for event in events:
			if event['ParentProcessGuid'] != parent_guid:
				children[0]['start_children'] = True
				children.append({'end_children': True})

				for index, proc in enumerate(procs):
					if proc.get('ProcessGuid') == parent_guid:
						index += 1
						procs[index:index] = children
						break

				parent_guid = event['ParentProcessGuid']
				children = []

			child_guids.append(event['ProcessGuid'])
			children.append(event)

		children[0]['start_children'] = True
		children.append({'end_children': True})

		for index, proc in enumerate(procs):
			if proc.get('ProcessGuid') == parent_guid:
				index += 1
				procs[index:index] = children
				break
	
		events = getChildren(child_guids) 
	
	return procs


def getEvents(guids, query):
	es = esConnect()
	body = {
		"from" : 0, # change for pagination
		"size": 100,
		"sort": [
			{
				"UtcTime": "asc"
			}
		],
		"query": {
			"bool": {
				"must": [
					{"terms": {"ProcessGuid.keyword": guids} },
					{"query_string": {"query": query} }
				]
			}
		}
	}
	res = es.search(index=settings.ES_INDEX, body=body)
	events = []
	for hit in res['hits']['hits']:
		events.append(hit['_source'])

	return events


@csrf_exempt
def processEventsTable(request):
	guids = request.POST.getlist("guids[]", [])
	query = request.POST.get("query", "").strip()
	events = getEvents(guids, query)

	if events:
		context = {'events': events}
		return render(request, "process_events_table.html", context) 

	return HttpResponse('No results found.')


def process(request, guid):
	procs = processTree(guid)

	proc_guids = []
	for proc in procs:
		pg = proc.get('ProcessGuid')
		if pg:
			proc_guids.append(pg)

	events = getEvents(proc_guids, '*')
	context = {'procs': procs, 'guids': proc_guids, 'events': events}

	return render(request, "process.html", context) 


def searchPage(request):
	return render(request, "search.html") 


def searchEvents(request):
	size = 100
	query = request.GET.get('query', '').strip()
	page = request.GET.get('page', 1)

	try:
		page = int(page)
	except:
		page = 1

	if query:
		es = esConnect()
		body = {
			"from" : (page - 1) * size,
			"size": size,
			"sort": [
				{
					"UtcTime": "asc"
				}
			],
			"query": {
				"query_string": {
					"query": query
				}
			}
		}
		res = es.search(index=settings.ES_INDEX, body=body)
		events = []
		for hit in res['hits']['hits']:
			events.append(hit['_source'])

		if events:
			hits_count = res['hits']['total']['value']
			pages = pagination(page, hits_count, size)
			context = {'events': events, 'pages': pages}
			return render(request, "process_events_table.html", context) 
		
	return HttpResponse('No results found.')

