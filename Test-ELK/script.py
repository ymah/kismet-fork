import json
from pprint import pprint
from os import listdir
from os.path import isfile, join
from datetime import datetime
import time
from elasticsearch import Elasticsearch

es = Elasticsearch([{'host':'127.0.0.1'}])


PATH_LOG ='/var/log/kismet/'


jsonfiles = [ f for f in listdir(PATH_LOG) if isfile(join(PATH_LOG,f)) ]

numberInsert = 0
numberFile = 0
for i in jsonfiles:
    numberFile+=1
    print("Traitemant du fichier : {0} ".format(i))
    json_data=open(PATH_LOG+i)
    data = json.load(json_data)
    for f in data['Networks']:
        pprint(f)
        json_data.close()
        post = f
        es.index(index='wifi_audit',doc_type='posts',id=numberInsert,body=post)
        es.indices.refresh(index='wifi_audit')
        numberInsert+=1
        print("{0} insertions".format(numberInsert))
    print("Fin du traitement du fichier {0} ".format(i))
    time.sleep(2)

print("{0} fichiers traités pour {1} insertions".format(numberFile,numberInsert))
