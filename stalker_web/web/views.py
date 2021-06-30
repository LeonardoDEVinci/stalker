import json
import requests
from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.db import connection
from elasticsearch import Elasticsearch, helpers, exceptions
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required


def evtToDict(res):
	events = []
	for hit in res['hits']['hits']:
		evt_dict = {}
		msg = hit['_source']['message']
		for line in msg.splitlines():
			k, v = line.split(":", 1)
			evt_dict[k] = v.strip()
		evt_dict['EventType'] = hit['_source']['event']['action'].split(' (', 1)[0]
		events.append(evt_dict)
	return events


def esConnect():
	return Elasticsearch([settings.ES_HOST], http_auth=('elastic', settings.ES_PASSWORD))


def pagination(page, hits_count, size):
	pages = []
	max_pages = 20

	last_page = int(hits_count / size)

	if last_page == 0:
		last_page = 1
	elif hits_count % size != 0:
		last_page += 1

	if page > last_page:
		page = last_page

	if page > 1:
		pages.append({'text': '<<', 'page': page - 1, 'active': False})

	if page <= max_pages:
		start = 1
		if last_page < max_pages:
			end = last_page
		else:
			end = max_pages

	else:
		start = page - max_pages + 1
		if page != last_page:
			end = page
		else:
			end = last_page

	for i in range(start, end + 1):
		if i == page:
			pages.append({'text': str(i), 'page': i, 'active': True})
		else:
			pages.append({'text': str(i), 'page': i, 'active': False})

	if page != last_page:
		pages.append({'text': '>>', 'page': page + 1, 'active': False})

	return pages


def getProcCreate(guid):
	es = esConnect()
	body = {
		"query": {
			"bool": {
				"must": [
					{"term": {"process.entity_id": guid} },
					{"term": {"winlog.event_id": "1"} }
				]
			}
		}
	}

	res = es.search(index=settings.ES_INDEX, body=body)
	hits = res['hits']['hits']
	if hits:
		hits[0]['_source']['timestamp'] = hits[0]['_source']['@timestamp']
		return hits[0]['_source']
	else:
		return None


def getChildren(guids):
	es = esConnect()
	body = {
		"size": 25,
		"sort": [
			{
				"process.parent.entity_id": "asc",
				"@timestamp": "asc"
			}
		],
		"query": {
			"bool": {
				"must": [
					{"terms": {"process.parent.entity_id": guids} },
					{"term": {"winlog.event_id": "1"} }
				]
			}
		}
	}

	res = es.search(index=settings.ES_INDEX, body=body)
	events = []

	for hit in res['hits']['hits']:
		hit['_source']['timestamp'] = hit['_source']['@timestamp']
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
		parent_guid = events[0]['process']['parent']['entity_id']
		for event in events:
			if event['process']['parent']['entity_id'] != parent_guid:
				children[0]['start_children'] = True
				children.append({'end_children': True})

				for index, proc in enumerate(procs):
					if proc.get('process') and proc['process']['entity_id'] == parent_guid:
						index += 1
						procs[index:index] = children
						break

				parent_guid = event['process']['parent']['entity_id']
				children = []

			child_guids.append(event['process']['entity_id'])
			children.append(event)

		children[0]['start_children'] = True
		children.append({'end_children': True})

		for index, proc in enumerate(procs):
			if proc.get('process') and proc['process']['entity_id'] == parent_guid:
				index += 1
				procs[index:index] = children
				break
	
		events = getChildren(child_guids) 
	
	return procs


def getProcessEvents(guids, query, page, size):
	es = esConnect()
	body = {
		"from" : (page - 1) * size,
		"size": size,
		"sort": [
			{
				"@timestamp": "asc"
			}
		],
		"query": {
			"bool": {
				"must": [
					{"terms": {"process.entity_id": guids} },
					{"query_string": {"query": query} }
				]
			}
		}
	}
	res = es.search(index=settings.ES_INDEX, body=body)
	events = evtToDict(res)

	pages = []
	if events:
		hits_count = res['hits']['total']['value']
		pages = pagination(page, hits_count, size)

	return events, pages


@login_required(login_url='login_url')
def processEventsTable(request):
	size = 100
	guids = request.POST.getlist("guids[]", [])
	query = request.POST.get("query", "*").strip()
	page = request.POST.get("page", 1)

	if query == "":
		query = "*"

	try:
		page = int(page)
	except:
		page = 1

	events, pages = getProcessEvents(guids, query, page, size)

	if events:
		context = {'events': events, 'pages': pages}
		return render(request, "process_events_table.html", context) 

	return HttpResponse('No results found.')


@login_required(login_url='login_url')
def process(request, guid):
	procs = processTree(guid)

	proc_guids = []
	for proc in procs:
		if proc.get('process'):
			proc_guids.append(proc['process']['entity_id'])

	events, pages = getProcessEvents(proc_guids, '*', 1, 100)
	context = {'procs': procs, 'guids': proc_guids, 'events': events, 'pages': pages}

	return render(request, "process.html", context) 


@login_required(login_url='login_url')
def searchPage(request):
	return render(request, "search.html") 


@login_required(login_url='login_url')
def searchEvents(request):
	size = 100
	query = request.GET.get('query', '*').strip()
	page = request.GET.get('page', 1)

	if query == "":
		query = "*"

	try:
		page = int(page)
		if page < 1:
			page = 1
	except:
		page = 1

	if query:
		es = esConnect()
		body = {
			"from" : (page - 1) * size,
			"size": size,
			"sort": [
				{
					"@timestamp": "desc"
				}
			],
			"query": {
				"query_string": {
					"query": query
				}
			}
		}
		res = es.search(index=settings.ES_INDEX, body=body)
		events = evtToDict(res)

		if events:
			hits_count = res['hits']['total']['value']
			pages = pagination(page, hits_count, size)
			context = {'events': events, 'pages': pages}
			return render(request, "process_events_table.html", context) 
		
	return HttpResponse('No results found.')


@login_required(login_url='login_url')
def manage(request):
	es = esConnect()
	exists = True
	try:
		user = es.security.get_user('winlogbeat_internal')
	except exceptions.NotFoundError:
		exists = False

	if request.method == 'POST':
		if not exists:
			data = {"cluster":["manage_index_templates","monitor","manage_ilm"],"indices":[{"names":["winlogbeat-*"],"privileges":["write","create_index","manage","manage_ilm"]}]}
			requests.post("http://%s:9200/_xpack/security/role/winlogbeat_writer" % settings.ES_HOST, auth=('elastic', settings.ES_PASSWORD), json=data)
			data = {"password":request.POST['password'],"roles":["winlogbeat_writer"],"full_name":"InternalWinlogbeatUser"}
			requests.post("http://%s:9200/_xpack/security/user/winlogbeat_internal" % settings.ES_HOST, auth=('elastic', settings.ES_PASSWORD), json=data)
			exists = True

	context = {'exists': exists}

	return render(request, "manage.html", context) 


def downloads(request):
	return render(request, "downloads.html") 


def login_view(request):
	if request.method == 'GET':
		return render(request, "login.html") 
	else:
		username = request.POST['username']
		password = request.POST['password']
		user = authenticate(request, username=username, password=password)
		if user is not None:
			login(request, user)
			return HttpResponseRedirect(reverse('search_page'))
		else:
			return HttpResponseRedirect(reverse('login_url'))


def logout_view(request):
	logout(request)
	return HttpResponseRedirect(reverse('login_url'))

