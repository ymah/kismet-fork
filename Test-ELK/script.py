import json
from pprint import pprint
from os import listdir
from os.path import isfile, join
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch([{'host':'127.0.0.1'}])


PATH_LOG ='/var/log/kismet/'


onlyfiles = [ f for f in listdir(PATH_LOG) if isfile(join(PATH_LOG,f)) ]

i = 0

json_data=open(PATH_LOG+onlyfiles[0])
data = json.load(json_data)


for f in data['Networks']:
    pprint(f)
    json_data.close()
    post = f
    es.index(index='my_index',doc_type='posts',id=i,body=post)
    es.indices.refresh(index='my_index')
    i+=1
