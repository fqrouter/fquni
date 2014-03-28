fquni
=====

unidirectional proxy

on client:
./proxy-up.sh
python fquni_client.py x.x.x.x:19842

on server:
python fquni_server.py

why nfqueue? because Android does not support -t TTL --ttl-set

License
=======
 
MIT
