template_open = '{{#ctx.payload.aggregations.result.hits.hits.0._source}}'
template_close = template_open.replace('{{#','{{/')
kibana_url = (
        "{{ctx.metadata.kibana_url}}/app/kibana#/discover?"
        "_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,"
        "index:'metricbeat-*',key:query,negate:!f,type:custom,value:''),"
        "query:(bool:(must:!((regexp:(kubernetes.pod.name:'{{ctx.metadata.regex}}')),"
        "(match:(metricset.name:'state_pod')),"
        "(match:(kubernetes.namespace:{{ctx.metadata.namespace}}))))))),"
        "index:'metricbeat-*',"
        "interval:auto,query:(language:lucene,query:''),"
        "regexp:(language:lucene,query:'kubernetes.pod.name:test-nginx-%5B%5E-%5D%20-%5B%5E-%5D%20'),"
        "sort:!('@timestamp',desc),time:(from:now%2FM,mode:quick,to:now%2FM))"
        "&_g=(refreshInterval:(display:Off,pause:!f,value:0),"
        "time:(from:now-15m,mode:quick,to:now))"
        )
watch_url = "{{ctx.metadata.kibana_url}}/app/kibana#/management/elasticsearch/watcher/watches/watch/{{ctx.metadata.name}}/status"

slack_alert_template = "{template_open}*<{kibana_url}|{{{{ctx.metadata.name}}}}>* has `{{{{ctx.payload.aggregations.pods.value}}}}` not ready pod(s) <{watch_url}|[ack]>{{{{#ctx.metadata.docs}}}} <{{{{.}}}}|[docs]>{{{{/ctx.metadata.docs}}}}{template_close}".format(**locals())
email_alert_template = "{template_open}<a href=\"{kibana_url}\">{{{{ctx.metadata.name}}}}</a> has {{{{ctx.payload.aggregations.pods.value}}}} not ready pod(s) <a href=\"{watch_url}\">[ack]</a>{{{{#ctx.metadata.docs}}}} <a href=\"{{{{.}}}}\">[docs]</a>{{{{/ctx.metadata.docs}}}}{template_close}".format(**locals())

k8s_template = {
  "metadata": {
    "name": "",
    "namespace": "",
    "regex": "",
    "kibana_url": "",
    "kibana_dashboard": "",
    "docs": "",
    "xpack" : {
        "type" : "json"
     },
  },
  "trigger": {
    "schedule": {
      "interval": ""
    }
  },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": [
          "metricbeat-*"
        ],
        "rest_total_hits_as_int": True,
        "body": {
          "aggs": {
            "result": {
              "top_hits": {
                "size": 1
              }
            },
            "pods": {
              "cardinality": {
                "field": "kubernetes.pod.name"
              }
            },
            "not_ready": {
              "terms": {
                "field": "kubernetes.pod.name",
                "min_doc_count": 12,
                "size": 100
              }
            }
          },
          "query": {
            "bool": {
              "must_not": [],
              "must": [],
              "filter": [
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-{{ctx.metadata.window}}"
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  },
  "condition": {},
  "actions": {
    "email_admin": {
      "throttle_period_in_millis": 300000,
      "email": {
        "profile": "standard",
        "subject": "{{#ctx.payload.aggregations.result.hits.hits.0._source}}{{ctx.metadata.name}} has {{ctx.payload.aggregations.pods.value}} not ready pod(s){{/ctx.payload.aggregations.result.hits.hits.0._source}}",
        "body": {
          "html": email_alert_template
        }
      }
    },
    "notify-slack": {
      "throttle_period_in_millis": 300000,
      "slack": {
        "message": {
          "text": slack_alert_template
        }
      }
    }
  }
}

metricbeat_template = {
  "metadata": {
    "window": "300s",
    "subject": "No metricbeat data has been recieved in the last 5 minutes!"
  },
  "trigger": {
    "schedule": {
      "interval": "60s"
    }
  },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": [
          "metricbeat-*"
        ],
        "rest_total_hits_as_int": True,
        "body": {
          "query": {
            "bool": {
              "must": [
                {
                  "match": {
                    "metricset.name": "state_pod"
                  }
                }
              ],
              "filter": [
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-{{ctx.metadata.window}}"
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "eq": 0
      }
    }
  },
  "actions": {
    "email_admin": {
      "throttle_period_in_millis": 300000,
      "email": {
        "profile": "standard",
        "subject": "{{ctx.metadata.subject}}",
        "body": {
          "text": "{{ctx.metadata.message}}"
        }
      }
    },
    "notify-slack": {
      "throttle_period_in_millis": 300000,
      "slack": {
        "message": {
          "text": "{{ctx.metadata.message}}"
        }
      }
    }
  }
}
