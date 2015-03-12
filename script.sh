#!/bin/bash

cd kismet
rm * ;
wait ;
/usr/local/bin/kismet_server -c $1;
wait;

echo "now lauch logstash"
