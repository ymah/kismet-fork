#Kismet-fork
Fork de kismet pour le PJI elasticsearch et audit wifi

###UTILISATION


Requis :

    * Elasticsearch installé
    * Kismet installé depuis le git (suivre le Readme présent dans le
    dossier Kismet)

Modifier le fichier /usr/local/etc/kismet.conf pour specifier ces
informations :

    * Serveur gpsd avec la variable gpshost
    * Path pour les logs de Kismet (de préférence /var/log/kismet) à
    specifier avec la variable logprefix

Une fois cela effectué, executez le serveur elasticsearch
Lancer le script script.py avec python3
Puis aller dans le dossier de kibana, modifier si necessaire le fichier
config/kibana.yml, et aller sur "MONSERVER:5601" avec un navigateur
