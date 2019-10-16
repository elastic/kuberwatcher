from kuberwatcher import *
import pystache
import pytest
import vcr
import certifi

my_vcr = vcr.VCR(
    cassette_library_dir='tests/cassettes',
    record_mode='new_episodes',
    filter_headers=['authorization'],
    match_on=['path', 'query']
)

def mustache_render(template, event):
    return pystache.render(template, {'ctx':{'payload':{'aggregations': {'result': {'hits': {'hits': {'0': {'_source': event }}}}}}}})

def test_template_defaults_with_no_outputs():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'pod_type': 'replicaset',
        'namespace': 'namespace'
    }
    template = render_template(**watch)
    assert template['metadata']['window'] == '300s'
    assert template['input']['search']['request']['body']['query']['bool']['must'][0]['regexp']['kubernetes.pod.name'] == 'pod-.*'
    assert template['input']['search']['request']['body']['query']['bool']['must'][1]['match']['kubernetes.namespace'] == 'namespace'

def test_template_with_job_pod_type():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'pod_type': 'job',
        'namespace': 'namespace'
    }
    template = render_template(**watch)
    assert template['input']['search']['request']['body']['query']['bool']['must_not'][0]['match'] == {'kubernetes.pod.status.phase': 'running'}
    assert template['input']['search']['request']['body']['query']['bool']['must_not'][1]['match'] == {'kubernetes.pod.status.phase': 'pending'}
    assert template['input']['search']['request']['body']['sort'] == [{"kubernetes.pod.name" : {"order" : "desc", "mode" : "max"}}]

def test_template_that_isnt_a_job():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'pod_type': 'replicaset',
        'namespace': 'namespace'
    }
    template = render_template(**watch)
    assert template['input']['search']['request']['body']['query']['bool']['must_not'][0]['match'] == {'kubernetes.pod.status.ready': 'true'}

def test_unflattening_a_yaml_config_from_kubernetes():
    config = '''
watcher.hello: 'hello'
watcher.goodbye: 'goodbye'
watcher.alerts.slack: 'slack'
watcher.alerts.email: 'email'
'''
    config = unflatten(yaml.load(config))
    assert config['watcher']['hello'] == 'hello'
    assert config['watcher']['goodbye'] == 'goodbye'
    assert config['watcher']['alerts']['slack'] == 'slack'
    assert config['watcher']['alerts']['email'] == 'email'

def test_merging_all_defaults():
    defaults = {'hello': 'world'}
    new = {}

    assert merge_defaults(defaults, new) == defaults

def test_overriding_merged_default():
    defaults = {'hello': 'world'}
    new = {'name': 'monitor', 'hello': 'mars'}

    assert merge_defaults(defaults, new) == new

def test_merging_in_a_new_field():
    defaults = {'hello': 'world'}
    new = {'name': 'monitor', 'test': 'mars'}

    assert merge_defaults(defaults, new) == {'name': 'monitor', 'test': 'mars', 'hello': 'world'}

def test_defaults_are_cloned_properly():
    defaults = {'hello': 'world'}
    new = {'name': 'monitor', 'test': 'mars'}
    assert merge_defaults(defaults, new) == {'name': 'monitor', 'test': 'mars', 'hello': 'world'}
    new2 = {'name': 'monitor2'}
    assert merge_defaults(defaults, new2) == {'name': 'monitor2', 'hello': 'world'}

def test_slack_mustache_template():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'slack': '@username'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'kibana_url': 'https://kibana.com',
                'name': 'namespace.podgroup'
            },
            'payload': {
                'aggregations': {
                    'pods': {
                        'value': 1
                    }
                }
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['notify-slack']['slack']['message']['text'], event)
    assert result == "*<https://kibana.com/app/kibana#/discover?_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'metricbeat-*',key:query,negate:!f,type:custom,value:''),query:(bool:(must:!((regexp:(kubernetes.pod.name:'')),(match:(metricset.name:'state_pod')),(match:(kubernetes.namespace:))))))),index:'metricbeat-*',interval:auto,query:(language:lucene,query:''),regexp:(language:lucene,query:'kubernetes.pod.name:test-nginx-%5B%5E-%5D%20-%5B%5E-%5D%20'),sort:!('@timestamp',desc),time:(from:now%2FM,mode:quick,to:now%2FM))&_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-15m,mode:quick,to:now))|namespace.podgroup>* has `1` not ready pod(s) <https://kibana.com/app/kibana#/management/elasticsearch/watcher/watches/watch/namespace.podgroup/status|[ack]>"

def test_conditionally_adding_docs_field_for_slack():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'slack': '@username'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'docs': 'https://docs.com/doc'
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['notify-slack']['slack']['message']['text'], event)
    assert '<https://docs.com/doc|[docs]>' in result

def test_customizing_the_metricbeat_index_pattern():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'slack': '@username'
        },
        'metricbeat_index_pattern': 'some-other-index-pattern'
    }

    template = render_template(**watch)
    metricbeat_index_pattern = template['input']['search']['request']['indices'][0]
    assert metricbeat_index_pattern == 'some-other-index-pattern'

def test_conditionally_not_adding_docs_field_for_slack():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'slack': '@username'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'docs': ''
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['notify-slack']['slack']['message']['text'], event)
    assert '[docs]' not in result

def test_email_mustache_template():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'email': 'username@email.com'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'kibana_url': 'https://kibana.com',
                'name': 'namespace.podgroup'
            },
            'payload': {
                'aggregations': {
                    'pods': {
                        'value': 1
                    }
                }
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['email_admin']['email']['body']['html'], event)
    expected = '''<a href="https://kibana.com/app/kibana#/discover?_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'metricbeat-*',key:query,negate:!f,type:custom,value:''),query:(bool:(must:!((regexp:(kubernetes.pod.name:'')),(match:(metricset.name:'state_pod')),(match:(kubernetes.namespace:))))))),index:'metricbeat-*',interval:auto,query:(language:lucene,query:''),regexp:(language:lucene,query:'kubernetes.pod.name:test-nginx-%5B%5E-%5D%20-%5B%5E-%5D%20'),sort:!('@timestamp',desc),time:(from:now%2FM,mode:quick,to:now%2FM))&_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-15m,mode:quick,to:now))">namespace.podgroup</a> has 1 not ready pod(s) <a href="https://kibana.com/app/kibana#/management/elasticsearch/watcher/watches/watch/namespace.podgroup/status">[ack]</a>'''.rstrip()
    assert result == expected


def test_conditionally_adding_docs_field_for_email():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'email': 'michael.russell@elastic.co'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'docs': 'https://docs.com/doc'
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['email_admin']['email']['body']['html'], event)
    assert '<a href="https://docs.com/doc">[docs]</a>' in result

def test_conditionally_not_adding_docs_field_for_email():
    watch = {
        'name': 'namespace.podgroup',
        'regex': 'pod-.*',
        'namespace': 'namespace',
        'pod_type': 'replicaset',
        'alerts': {
            'email': 'michael.russell@elastic.co'
        }
    }
    event = {
        'ctx': {
            'metadata': {
                'docs': ''
            }
        }
    }
    template = render_template(**watch)
    result = mustache_render(template['actions']['email_admin']['email']['body']['html'], event)
    assert '[docs]' not in result

def test_kubernetes_base_name():
    assert base_name('test-nginx-b4cc76b85-4f588', 'replicaset') == 'test-nginx'
    assert base_name('test-nginx-0', 'statefulset') == 'test-nginx'
    assert base_name('metricbeat-jlrb7', 'daemonset') == 'metricbeat'
    assert base_name('vault-backup-vault-poc-vault-test-1514995200-c4rch', 'job') == 'vault-backup-vault-poc-vault-test'


def test_generating_pod_regex():
    assert pod_regex('test-nginx', 'replicaset') == 'test-nginx-[^-]+-[^-]+'
    assert pod_regex('test-nginx', 'statefulset') == 'test-nginx-[^-]+'
    assert pod_regex('metricbeat', 'daemonset') == 'metricbeat-[^-]+'
    assert pod_regex('vault-backup-vault-poc-vault-test', 'job') == 'vault-backup-vault-poc-vault-test-[^-]+-[^-]+'

def test_generating_full_pod_name():
    assert full_name('pod', 'namespace') == 'namespace.pod'

@my_vcr.use_cassette()
def test_getting_all_namespace():
    load_config()
    defaults = {}
    namespaces = get_namespaces(defaults)
    assert 'test' in namespaces

@my_vcr.use_cassette()
def test_getting_namespace_with_overriden_config():
    load_config()
    defaults = {
      'interval': '30s',
      'throttle': 360000,
      'window': '300s',
      'failures': 3,
      'alerts': {
        'email': 'michael.russell@elastic.co',
        'slack': '@michael.russell'
      }
    }
    namespaces = get_namespaces(defaults)
    assert namespaces['override']['alerts']['slack'] == '@michael.override'

@my_vcr.use_cassette()
def test_getting_email_alerts_disabled_when_overriding_alerts():
    load_config()
    defaults = {
      'alerts': {
        'email': 'michael.russell@elastic.co',
        'slack': '@michael.russell'
      }
    }
    namespaces = get_namespaces(defaults)
    assert namespaces['override']['alerts']['slack'] == '@michael.override'
    assert 'email' not in namespaces['override']['alerts']

@my_vcr.use_cassette()
def test_get_all_pods():
    namespaces = {'test': {}}
    pods = get_all_pods(namespaces)
    assert 'nginx' in pods['replicaset']['test']

@my_vcr.use_cassette()
def test_get_all_pods_including_jobs():
    namespaces = {'test': {}}
    pods = get_all_pods(namespaces)
    assert 'replicaset' in pods
    assert 'job' in pods

@my_vcr.use_cassette()
def test_get_watcher_enabled_without_namespace_enabled():
    namespaces = {}
    pods = get_all_pods(namespaces)
    assert 'nginx' in pods['replicaset']['disabled']
    assert 'disabled' not in pods['replicaset']['disabled']

@my_vcr.use_cassette()
def test_get_all_pods_with_pods_that_dont_have_created_by():
    namespaces = {'test': {}}
    pods = get_all_pods(namespaces)
    assert 'nginx-pod' not in pods['replicaset']['test']

def test_generate_watch():
    pods = { 
        'replicaset': {
            'test': {
                'nginx': {}
            }
        }
    }
    watches = generate_watch(pods)
    assert watches['test.nginx']['metadata']['name'] == 'test.nginx'
    assert watches['test.nginx']['metadata']['namespace'] == 'test'
    assert watches['test.nginx']['metadata']['regex'].startswith('nginx')

def test_watch_that_didnt_change():
    watch = 'test'
    template = {'hello': 'world'}
    watches = {'test': {'hello': 'world'}}
    assert watch_changed(watch, template, watches) == False

def test_watch_that_changed():
    watch = 'test'
    template = {'hello': 'world2'}
    watches = {'test': {'hello': 'world'}}
    assert watch_changed(watch, template, watches) == True

def test_watch_that_didnt_exist():
    watch = 'new'
    template = {'hello': 'world'}
    watches = {'test': {'hello': 'world'}}
    assert watch_changed(watch, template, watches) == True

@my_vcr.use_cassette()
def test_real_watch_that_did_actually_change():
    defaults = {
        "kibana_url": "https://kibana.example.com",
        "alerts": {
            "email": "michael.russell@elastic.co",
            "slack": "@michael.russell",
        },
        "failures": 3,
        "interval": "30s",
        "throttle": 360000,
        "window": "300s"
    }
    es = connect_to_es()
    watches = main(es, defaults)
    watch = 'test.nginx'
    current_watches = get_current_watches(es)
    template = watches[watch]
    template['metadata']['name'] = 'changed'
    assert watch_changed(watch, template, current_watches) == True

@my_vcr.use_cassette()
def test_sending_a_watch_to_watcher():
    defaults = {
        "kibana_url": "https://kibana.example.com",
        "alerts": {
            "email": "michael.russell@elastic.co",
            "slack": "@michael.russell"
        }
    }
    es = connect_to_es()
    current_watches = get_current_watches(es)
    watches = main(es, defaults)
    updated = send_watches(watches, current_watches, es)
    assert len(updated) != 0
    assert 'test.nginx' in watches
    assert 'metricbeat' in watches
    assert watches['metricbeat']['metadata']['message'] == 'No metricbeat data has been recieved in the last 5 minutes! <https://kibana.example.com|kibana>'
    assert watches['metricbeat']['actions']['email_admin']['email']['to'] == ['michael.russell@elastic.co']
    assert watches['metricbeat']['actions']['email_admin']['throttle_period_in_millis'] == 3600000

    # When sending the watches again they should not be updated
    current_watches = get_current_watches(es)
    updated = send_watches(watches, current_watches, es)
    assert len(updated) == 0

@my_vcr.use_cassette()
def test_sending_a_watch_to_watcher_with_overridden_metricbeat_index_pattern():
    defaults = {
        "kibana_url": "https://kibana.example.com",
        "alerts": {
            "email": "michael.russell@elastic.co",
            "slack": "@michael.russell"
        },
        "metricbeat_index_pattern": 'overridden-pattern-*'
    }

    es = connect_to_es()
    current_watches = get_current_watches(es)
    watches = main(es, defaults)
    updated = send_watches(watches, current_watches, es)
    assert len(updated) > 0
    assert 'test.nginx' in watches
    assert 'metricbeat' in watches
    assert watches['metricbeat']['input']['search']['request']['indices'][0] == 'overridden-pattern-*'
    assert watches['test.nginx']['input']['search']['request']['indices'][0] == 'overridden-pattern-*'

    # When sending the watches again they should not be updated
    current_watches = get_current_watches(es)
    updated = send_watches(watches, current_watches, es)
    assert len(updated) == 0

def test_add_alerts():
    alerts = {
        "email": "michael.russell@elastic.co,micky@elastic.co",
        "slack": "@michael.russell,@micky"
    }
    result = add_alerts(copy.deepcopy(metricbeat_template), alerts, 0)
    assert result['actions']['email_admin']['email']['to'] == ['michael.russell@elastic.co', 'micky@elastic.co']
    assert result['actions']['notify-slack']['slack']['message']['to'] == ['@michael.russell', '@micky']

def test_add_alerts_with_only_slack():
    alerts = {
        "slack": "@michael.russell"
    }
    result = add_alerts(copy.deepcopy(metricbeat_template), alerts, 0)
    assert 'email_admin' not in result['actions']
    assert result['actions']['notify-slack']['slack']['message']['to'] == ['@michael.russell']

def test_add_alerts_with_only_email():
    alerts = {
        "email": "michael.russell@elastic.co",
    }
    result = add_alerts(copy.deepcopy(metricbeat_template), alerts, 0)
    assert 'notify-slack' not in result['actions']
    assert result['actions']['email_admin']['email']['to'] == ['michael.russell@elastic.co']

def test_add_alerts_with_reply_to():
    alerts = {
        "email": "michael.russell@elastic.co",
    }
    result = add_alerts(copy.deepcopy(metricbeat_template), alerts, 0, 'reply@elastic.co')
    assert 'notify-slack' not in result['actions']
    assert result['actions']['email_admin']['email']['to'] == ['michael.russell@elastic.co']
    assert result['actions']['email_admin']['email']['reply_to'] == ['reply@elastic.co']

def test_add_alerts_with_overriden_throttle_period():
    alerts = {
        "email": "michael.russell@elastic.co"
    }
    result = add_alerts(copy.deepcopy(metricbeat_template), alerts, 123456)
    assert result['actions']['email_admin']['throttle_period_in_millis'] == 123456

def test_es_client_config_with_client_cert_path(monkeypatch):
    mock_client_cert_path = 'path/to/client.pem'
    monkeypatch.setitem(os.environ, 'ES_CLIENT_CERT_PATH', mock_client_cert_path)
    es_hosts, es_client_kwargs = es_connection_config()

    assert es_client_kwargs.get('client_cert') == mock_client_cert_path
    assert es_client_kwargs.get('client_key') == None
    assert es_client_kwargs.get('http_auth') == None

def test_es_client_config_with_client_cert_and_key_path(monkeypatch):
    mock_client_cert_path = '/path/to/client.pem'
    mock_client_key_path = '/path/to/client.key'
    monkeypatch.setitem(os.environ, 'ES_CLIENT_CERT_PATH', mock_client_cert_path)
    monkeypatch.setitem(os.environ, 'ES_CLIENT_KEY_PATH', mock_client_key_path)
    es_hosts, es_client_kwargs = es_connection_config()

    assert es_client_kwargs.get('client_cert') == mock_client_cert_path
    assert es_client_kwargs.get('client_key') == mock_client_key_path
    assert es_client_kwargs.get('http_auth') == None

def test_es_client_config_without_ca_certs_set():
    expected_ca_cert_path = certifi.where()
    es_hosts, es_client_kwargs = es_connection_config()

    assert es_client_kwargs.get('ca_certs') == expected_ca_cert_path

def test_es_client_config_with_ca_certs_set(monkeypatch):
    mock_ca_cert_path = '/path/to/ca.pem'
    monkeypatch.setitem(os.environ, 'ES_CA_CERTS', mock_ca_cert_path)
    es_hosts, es_client_kwargs = es_connection_config()

    assert es_client_kwargs.get('ca_certs') == mock_ca_cert_path
