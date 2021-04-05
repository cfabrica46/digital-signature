# create-keys-rsa
## Comandos Necesarios

### Generar Llave Privada
~~~
openssl genrsa -out key.pem 2048
~~~

### Generar Llave Pública
~~~
openssl rsa -in key.pem -outform PEM -pubout -out public.pem
~~~

### Generar Firma Con Openssl
~~~
openssl dgst -sha256 -sign key.pem -out firma.sha256 archivo.txt
~~~

### Verificar Firma Con Openssl
~~~
openssl dgst -sha256 -verify public.pem -signature firma.sha256 archivo.txt
~~~

