# Kuberwatcher

[![Build Status](https://img.shields.io/jenkins/s/https/devops-ci.elastic.co/job/elastic+kuberwatcher+master.svg)](https://devops-ci.elastic.co/job/elastic+kuberwatcher+master/)

This is a small python script that will generate separate watches for each group of pods.
If you have a namespace called `test` and a deployment called `nginx` and `elasticsearch` this script will automagically create watches called `test.nginx` and `test.elasticsearch` which will send email and or slack alerts if any of the pods in these deployments are not ready. 

# When is an alert sent?

## Deployments/Daemonsets/Statefulsets

An alert will be sent if a single pod is not ready for 2 minutes in a 5 minute window. This can be increased or decreased by changing the `failures` settings.

## Cronjobs

An alert will be sent if a cronjob fails 2 times in a row. This behavior can be changed by modifying the `job_failures`


# Enabling monitoring

Monitoring can be enabled on a namespace or pod level. To enable monitoring on the a namespace called `infra` you can add the label `watcher=enabled`
```
kubectl label namespace infra watcher=enabled
```
This can also be enabled directly inside the namespace definition
```
apiVersion: v1
kind: Namespace
metadata:
  name: infra
  labels:
    watcher: enabled
```

Enabling watcher for a single deployment in a namespace that isn't enabled
```
spec:
  template:
    metadata:
      labels:
        watcher: enabled
```

Disabling watcher for a single deployment in a namespace that is enabled
```
spec:
  template:
    metadata:
      labels:
        watcher: disabled
```

# Overriding monitoring defaults

All of the defaults (read from `./kuberwatcher.yml`) can be overridden on a namespace and a pod level under the annotations metadata in the Kubernetes object

Sending all slack alerts in the `michael` namespace to slack user `@michael.russell`

```
apiVersion: v1
kind: Namespace
metadata:
  name: michael
  labels:
    watcher: enabled
  annotations:
    watcher.alerts.slack: '@michael.russell'
```

Adding alert documentation links for pods in a deployment
```
spec:
  template:
    metadata:
      annotations:
        watcher.docs: https://github.com/elastic/kuberwatcher/blob/master/README.md
```


# Configuration

```
watcher.alerts.email: 'username@elastic.co,team@elastic.co' # Comma separated list of email addresses
watcher.alerts.slack: '@michael.russell,infra'              # Comma separated list of `@usernames` and `channelnames`
watcher.kibana_url    'https://kibana.elastic.co'           # Base URl for generating links to Kibana
watcher.docs:         'https://example.com/HALP.md'         # Documentation link that will be included in the alert
watcher.failures:      12                                   # How many failed attempts need to have happened in the current window per pod (optional)
watcher.jobfailures:   2                                    # How many times a cronjob needs to fail in a row being an alert is sent (optional)
watcher.interval:     '30s'                                 # How often the query is run (optional)
watcher.reply_to      'team@elastic.co,reply@elastic.o'     # Comma separated list of email addresses to use for the reply_to field in the email alerts
watcher.throttle:     600000                                # How often to send the alert in ms (optional)
watcher.window:       '300s'                                # How long the the pods need to be not ready before alerting (optional)
```

# Running Kuberwatcher

## Requirements

* [Metricbeat](https://www.elastic.co/guide/en/beats/metricbeat/current/running-on-kubernetes.html) (with kube-state-metrics) deployed on kubernetes with the [`state_pod`](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-kubernetes-state_pod.html) metricset enabled.
* Elasticsearch with X-Pack and watcher enabled
* If you want to send emails you will need to configure an [email account](https://www.elastic.co/guide/en/elastic-stack-overview/current/actions-email.html#configuring-email) in X-Pack.
* If you want to send slack alerts you will need to configure a [slack account](https://www.elastic.co/guide/en/elastic-stack-overview/current/actions-slack.html#configuring-slack) in X-Pack.

### Try kuberwatcher locally

If you just want to try out kuberwatcher running locally it will use your current kubectl context to generate alerts. 

* First update the local kuberwatcher.yml
* Set the elasticsearch connection details
```
export ES_USERNAME='elastic'
export ES_PASSWORD='changeme'
export ES_HOSTS='http://elasticsearch:9200'
```
* Run kuberwatcher in docker
```
make run
```

### Run kuberwatcher in kubernetes

There is an example in [k8s/kuberwatcher.yml](./k8s/kuberwatcher.yml) for running kuberwatcher as a CronJob in kubernetes.

* Create the secrets for kuberwatcher to connect to Elasticsearch
```
kubectl create secret generic kuberwatcher --from-literal=endpoint=http://elasticsearch:9200 --from-literal=password=changeme --from-literal=username=elastic
```
* Modify the configuration in the configmap defined in [k8s/kuberwatcher.yml](./k8s/kuberwatcher.yml)
* Deploy!
```
kubectl apply -f k8s/kuberwatcher.yml
```

# Developing kuberwatcher

Requirements:
* Docker
* Make

To run all of the tests:
```
make test
```

Because this project interacts with two fast moving projects (Elasticsearch and kubernetes) it uses [vcrpy](http://vcrpy.readthedocs.io/en/latest/usage.html) to record interactions with these APIs instead of trying to constantly update mocks for both projects.

If you are making changes that affect API calls to kubernetes or Elasticsearch you will need to make sure you have a working development environment to record the new API transactions. To start Elasticsearch and Kibana you can run:
```
# if you want to test with slack you need to add your slack url too
export SLACK_URL='https://hooks.slack.com/services/SDKLSD/SDFLIJSDF323f3f'
make deps
```

To generate the test pods in a local minikube cluster you can run install the fixtures by running:

```
make fixtures
```
This will start metricbeat, kube-state-metrics and a bunch of tests pods which were used to generate the cassette data.

If you want to refresh the recorded API data in the cassettes you can run:

```
make clean_cassettes
```

When you are finished you can clean up everything by running:

```
make clean
```
