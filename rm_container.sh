#!/bin/bash
id=`docker container ls | grep myapp | awk '{print $1}'`
echo $id

docker container stop $id
docker container rm $id
