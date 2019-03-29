default: build

SHELL:=/bin/bash -eu
export PATH := ./bin:./venv/bin:$(PATH)

VERSION = 6.5.4-1
IMAGE = push.docker.elastic.co/kuberwatcher/kuberwatcher:${VERSION}
STACK_VERSION = 6.5.4
PASSWORD = changeme

build:
	docker build -t ${IMAGE} .

deps:
	docker rm -f kuberwatcher_es kuberwatcher_kibana || true
	docker run --name kuberwatcher_es -d -p 9200:9200 -p 9300:9300 -e "xpack.notification.slack.account.monitoring.url=$(SLACK_URL)" -e "ELASTIC_PASSWORD=$(PASSWORD)" -e "xpack.security.enabled=true" -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:$(STACK_VERSION)
	echo 'Waiting for elasticsearch to start'
	until curl -Is -u elastic:changeme localhost:9200 ; do printf '.' ; sleep 1; done
	docker run --name kuberwatcher_kibana --link kuberwatcher_es:elasticsearch -e "ELASTICSEARCH_USERNAME=elastic" -e "ELASTICSEARCH_PASSWORD=$(PASSWORD)" -d -p 5601:5601 docker.elastic.co/kibana/kibana:$(STACK_VERSION)
	echo 'Waiting for Kibana to start'
	until curl -Is 'localhost:5601/api/status'; do printf '.'; sleep 1; done
	echo 'Activating X-Pack trial license'
	until curl -Is -XPOST 'localhost:9200/_xpack/license/start_trial?acknowledge=true' ; do printf '.' ; sleep 1; done

run: build
	docker run --rm -ti -v ${HOME}/.minikube:${HOME}/.minikube -v ~/.kube:/root/.kube/ --link kuberwatcher_es:elasticsearch -v $$(PWD):/app -w /app -e ES_PASSWORD="${ES_PASSWORD}" -e ES_USERNAME="${ES_USERNAME}" -e ES_HOSTS="${ES_HOSTS}" ${IMAGE}

deploy: build
	docker push ${IMAGE}

test-python: venv
	source ./venv/bin/activate
	pytest -v --cov=./ --cov-fail-under=100 --cov-report html

report: test
	open htmlcov/index.html

venv: requirements.txt requirements-dev.txt
	test -d venv || python3 -m venv venv
	source ./venv/bin/activate
	venv/bin/pip install -r requirements.txt -r requirements-dev.txt

clean:
	docker rm -f kuberwatcher_kibana kuberwatcher_es || true
	kubectl delete -f tests/fixtures || true
	kubectl delete -f https://raw.githubusercontent.com/elastic/beats/v$(STACK_VERSION)/deploy/kubernetes/metricbeat-kubernetes.yaml || true

test: 
	export CI=$${CI:-'false'} && \
	if [[ $$(docker ps -f "name=kuberwatcher_es" --format '{{.Names}}') == "kuberwatcher_es" ]]; then link='--link kuberwatcher_es:elasticsearch'; else link=''; fi ; \
	docker run $$link --rm -v ${HOME}/.minikube:${HOME}/.minikube -v ~/.kube:/.kube/ --user=$$UID -e CI=$$CI -i -v "$$PWD":/app -w /app python:3.6 /usr/bin/make test-python

fixtures:
	cluster=$$(kubectl config current-context) && \
	read -p "Going to install fixtures into cluster '$${cluster}'. Hit enter to continue"
	kubectl apply -f tests/fixtures
	kubectl apply -f https://raw.githubusercontent.com/elastic/beats/v$(STACK_VERSION)/deploy/kubernetes/metricbeat-kubernetes.yaml

clean_cassettes:
	rm -rf tests/cassettes/*
