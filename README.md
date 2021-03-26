#RSAKey Pair Generation for JWT

You can generate a public and private RSA key pair like this:

openssl genrsa -out jwt_private.pem 2048


That generates a 2048-bit RSA key pair, encrypts them with a password you provide and writes them to a file. You need to next extract the public key file. You will use this, for instance, on your web server to encrypt content so that it can only be read with the private key.

Export the RSA Public Key to a File
This is a command that is

openssl rsa -in jwt_private.pem -outform PEM -pubout -out jwt_public.pem