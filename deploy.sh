#!/bin/bash
rm -f ll.zip
cd ..
zip -r ll lwip
mv ll.zip lwip
cd lwip
docker-compose down && docker-compose up -d
