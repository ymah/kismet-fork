# Author : Mahieddine Yaker (mahieddine.yaker@gmail.com)
# 10/04/2015
# script utilisé pour charger des fichiers json dans la base de donnée
# Elasticsearch
import json
from pprint import pprint
from os import listdir
from os.path import isfile, join
from datetime import datetime
import time
from elasticsearch import Elasticsearch


def getJsonFiles(path):
    """
    Script permettant de récuperer les fichiers jsons à partir d'un
    path fourni en parametre
    """
    jsonfiles = [ f for f in listdir(path) if isfile(join(path,f)) ]
    return jsonfiles


def dumpToElsch(jsonfiles,elschClient,index):
    """
    Script permettant de charger les données présentes dans la liste
    de fichiers jsonfiles, dans la base de donnée elasticsearch fournie
    avec le parametre elschClient
    """
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
            elschClient.index(index=index,\
                              doc_type='posts',\
                              id=numberInsert,\
                              body=post)
            elschClient.indices.refresh(index=index)
            numberInsert+=1
            print("{0} insertions".format(numberInsert))
        print("Fin du traitement du fichier {0} ".format(i))
        time.sleep(2)
    print("{0} fichiers traités pour {1} insertions".\
          format(numberFile, numberInsert))



if __name__ == "__main__":
    """
    programme main executant un enregistrement depuis le path
    /var/log/kismet dans une base de donnée locale
    """
    es = Elasticsearch([{'host':'127.0.0.1'}])
    PATH_LOG = '/var/log/kismet/'
    jsonfiles = getJsonFiles(PATH_LOG)
    dumpToElsch(jsonfiles,es,'wifi_audit')
