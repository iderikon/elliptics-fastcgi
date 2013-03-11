#/bin/bash

cd configs
#dnet_ioserv -c ioserv.conf 
fastcgi-daemon2 --config=cproxy.conf 

