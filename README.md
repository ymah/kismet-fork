# kismet-fork
Fork de kismet pour le PJI elasticsearch et audit wifi


#UTILISATION


Requis :
    -Elasticsearch installé
    -Kismet installé depuis le git



Modifier le fichier /usr/local/etc/kismet.conf pour specifier ces informations :
    -serveur gpsd avec la variable gpshost
    -path pour les logs de Kismet (de préférence /var/log/kismet) à specifier avec la variable logprefix

Une fois cela effectué, executez le serveur elasticsearch
lancer le script script.py avec python3
puis aller dans le dossier de kibana, modifier si necessaire le fichier config/kibana.yml, et aller sur "127.0.0.1:5601" avec un navigateur
