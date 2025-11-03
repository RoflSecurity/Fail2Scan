#!/bin/bash

npm install pm2 -g
chmod -R a+r ../dist-dev
pm2 serve ../dist-dev 5173 --name fail2scan-ui --spa
cd ../failtoscan-api && chmod +x index.js
pm2 start index.js --name fail2scan-api