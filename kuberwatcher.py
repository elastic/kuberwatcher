#!/usr/bin/env python3

from kubernetes import client, config
from collections import defaultdict
import json
import urllib.parse
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from elasticsearch_xpack import XPackClient
from template import k8s_template, metricbeat_template
import certifi
import copy
import os
import yaml

# Recursive defaultdict so we don't need to constantly check if key in dict before creating a nested dict
tree = lambda: defaultdict(tree)

def merge_defaults(defaults, config):
    new = defaults.copy()
    new.update(config)
    return(new)

def unflatten(dictionary):
    if not dictionary:
        return {}
    resultDict = dict()
    for key, value in dictionary.items():
        parts = key.split(".")
        d = resultDict
        for part in parts[:-1]:
            if part not in d:
                d[part] = dict()
            d = d[part]
        d[parts[-1]] = value
    return resultDict

def render_template(
    name,
    regex,
    namespace,
    pod_type,
    alerts={},
    docs='',
    kibana_url='https://kibana.example.com',
    failures=12,
    job_failures=2,
    interval='30s',
    reply_to=None,
    throttle=3600000,
    window='300s'
 ):


    template = copy.deepcopy(k8s_template)
    template['input']['search']['request']['body']['query']['bool']['must'].append({'regexp': {'kubernetes.pod.name': regex }})
    template['input']['search']['request']['body']['query']['bool']['must'].append({'match': {'kubernetes.namespace': namespace}})
    template['input']['search']['request']['body']['query']['bool']['must'].append({'match': {'metricset.name': 'state_pod'}})

    if pod_type == 'job':
        # Only return the amount of failures we care about. With the default amount of 2 we will get 2 results. If all of these results have failed we will send an alert
        template['input']['search']['request']['body']['size'] = job_failures

        # Filter out running and pending jobs since we just want to find the latest completed results
        template['input']['search']['request']['body']['query']['bool']['must_not'].append({'match': {'kubernetes.pod.status.phase': 'running'}})
        template['input']['search']['request']['body']['query']['bool']['must_not'].append({'match': {'kubernetes.pod.status.phase': 'pending'}})

        # Cronjob pods contain a unix timestamp in their name. By sorting the pods by name we can get the most recent jobs at the top of the results
        template['input']['search']['request']['body']['sort'] = [{"kubernetes.pod.name" : {"order" : "desc", "mode" : "max"}}]
        template['condition'] = {
            "script" : {
                "lang": "painless",
                # Alert if there aren't any succesful jobs in our result. The default value of 2 means we need 2 failed jobs in a row before alerting 
                "source" : "for (h in ctx.payload.hits.hits) { if (h._source.kubernetes.pod.status.phase == 'succeeded') return false; } return true;"
            }
        }

    else:
        template['input']['search']['request']['body']['query']['bool']['must_not'].append({'match': {'kubernetes.pod.status.ready': 'true'}})
        # We want to alert if there are any not ready pods in this group
        template['condition'] = {
            "compare": {
                "ctx.payload.aggregations.not_ready.buckets": {
                    "not_eq": []
                }
            }
        }


    template['input']['search']['request']['body']['aggs']['not_ready']['terms']['min_doc_count'] = failures
    template['trigger']['schedule']['interval'] = interval
    template['actions']['notify-slack']['throttle_period_in_millis'] = throttle
    template['actions']['email_admin']['throttle_period_in_millis'] = throttle
    template['metadata']['name'] = name
    template['metadata']['namespace'] = namespace
    template['metadata']['window'] = window
    template['metadata']['kibana_url'] = kibana_url
    template['metadata']['docs'] = docs
    template['metadata']['regex'] = urllib.parse.quote_plus(regex)

    return add_alerts(template, alerts, reply_to)


kind_dashes_map = {
    'replicationcontroller': 2,
    'replicaset': 2,
    'statefulset': 1,
    'daemonset': 1,
    'job': 2,
}

def base_name(name, kind):
    return name.rsplit('-', kind_dashes_map[kind])[0]

def add_alerts(template, alerts, reply_to=None):
    if 'email' in alerts:
        template['actions']['email_admin']['email']['to'] = alerts['email'].split(',')
        if reply_to:
            template['actions']['email_admin']['email']['reply_to'] = reply_to.split(',')
    else:
        del template['actions']['email_admin']

    if 'slack' in alerts:
        template['actions']['notify-slack']['slack']['message']['to'] = alerts['slack'].split(',')
    else:
        del template['actions']['notify-slack']

    return template

def get_all_pods(namespaces):
    v1 = client.CoreV1Api()
    kinds = tree()
    ret = v1.list_pod_for_all_namespaces(watch=False,label_selector='watcher!=disabled')
    for i in ret.items:
        namespace = i.metadata.namespace
        # If this namespace doesn't have watcher alerts enabled we want to see if they are enabled on the pod itself
        if namespace not in namespaces:
            if i.metadata.labels and not i.metadata.labels.get('watcher') == 'enabled':
                continue
        name = i.metadata.name
        kind = None
        try:
            kind = i.metadata.owner_references[0].kind
        except:
            print('Could not determine the kind for:', name)

        if kind:
            kind = kind.lower()
            pod_group_name = base_name(name, kind)
            annotations = unflatten(i.metadata.annotations)
            config = merge_defaults(namespaces.get(namespace,{}), annotations.get('watcher',{}))
            kinds[kind][namespace][pod_group_name] = config
        
    return kinds


def pod_regex(name, kind):
    dashes = kind_dashes_map[kind]
    dash_regex = '-[^-]+' * dashes
    return '{name}{dash_regex}'.format(**locals())


def full_name(pod, namespace):
    return '{0}.{1}'.format(namespace, pod)


def generate_watch(pods):
    watches = {}
    for pod_type, pods in pods.items():
        for namespace, groups in pods.items():
            for pod, config in groups.items():
                name = full_name(pod, namespace)
                config = merge_defaults(config, {'name': name, 'namespace': namespace, 'regex': pod_regex(pod, pod_type), 'pod_type': pod_type})
                watch = render_template(**config)
                watches[name] = watch
    return watches


def get_namespaces(defaults):
    v1 = client.CoreV1Api()
    namespaces = {}
    for ns in v1.list_namespace(label_selector='watcher=enabled').items:
        if ns.metadata.annotations:
            annotations = unflatten(ns.metadata.annotations)
            config = merge_defaults(defaults, annotations.get('watcher',{}))
        else:
            # Older versions of kubernetes don't always have annotations by default
            # We are only testing against the latest version so path doesn't occur
            # with the latest kubernetes version
            config = defaults # pragma: nocover
        namespaces[ns.metadata.name] = config
    return namespaces

def load_config(): # pragma: nocover
    if os.environ.get('CI') == 'true':
        return
    elif os.path.exists('/run/secrets/kubernetes.io/serviceaccount'):
        config.load_incluster_config()
    else:
        config.load_kube_config()

def get_current_watches(es):
    watches = {}
    try:
        for watch in es.search(index=".watches",size=1000)['hits']['hits']:
            watches[watch['_id']] = watch['_source']
            del watches[watch['_id']]['status']
    except NotFoundError as err:
        # If we get back a 404 then no watches have been created yet
        return watches

    return watches

def watch_changed(watch, template, watches):
    if watch in watches:
        changed = json.dumps(watches[watch], sort_keys=True) != json.dumps(template, sort_keys=True)
        if not changed:
            print('Skipping: {0}'.format(watch))
        else:
            print('Updating {0}'.format(watch))
        return changed
    else:
        print('Creating: {0}'.format(watch))
        return True

def send_watches(watches, current_watches, es):
    xpack = XPackClient(es)
    updated = []
    for watch, template in watches.items():
        if watch_changed(watch, template, current_watches):
            xpack.watcher.put_watch(watch, template)
            updated.append(watch)
    return updated

def connect_to_es():
    es = Elasticsearch(
            [os.environ.get('ES_HOSTS','http://elasticsearch:9200')],
            http_auth=(os.environ.get('ES_USERNAME','elastic'), os.environ.get('ES_PASSWORD','changeme')),
            ca_certs=certifi.where()
            )
    return es

def main(es, defaults):
    load_config()
    namespaces = get_namespaces(defaults)
    pods = get_all_pods(namespaces)
    watches = generate_watch(pods)
    watches['metricbeat'] = add_alerts(metricbeat_template, defaults['alerts'], defaults.get('reply_to', None))
    watches['metricbeat']['metadata']['message'] = 'No metricbeat data has been recieved in the last 5 minutes! <{0}|kibana>'.format(defaults['kibana_url'])
    return watches

if __name__ == "__main__": # pragma: nocover
    es = connect_to_es()
    defaults = unflatten(yaml.load(open('kuberwatcher.yml')))
    current_watches = get_current_watches(es)
    watches = main(es, defaults)
    send_watches(watches, current_watches, es)
