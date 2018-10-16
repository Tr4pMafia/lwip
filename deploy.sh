#!/bin/bash
rm -f ll.zip
cd ..
zip -r ll lwip
mv ll.zip lwip
cd lwip
sudo docker-compose up -d
