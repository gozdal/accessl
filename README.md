AcceSSL
=======

Scalable software [Security Module][HSM] for OpenSSL.

Why would I want it?
--------------------

To be a little bit more secure. To be able to scale performance of SSL layer if you need it.

How does it work?
-----------------

RSA public and private key operations in OpenSSL are relayed via UDP to AcceSSL workers which compute the result and return it to OpenSSL.
AcceSSL uses [OpenSSL engine mechanism][engine], so your server software needs to support it. Newer versions of Apache HTTP server and nginx support it out of the box.

How scalable is it?
-------------------

One worker process can handle multiple clients (i.e. OpenSSL-based servers, like nginx). Also OpenSSL-based servers can utilize many AcceSSL workers.
Unfortunately OpenSSL API for RSA operations is synchronous. It means you need at least that many threads/processes in OpenSSL-based server as there are AcceSSL workers to utilize all workers.

Unscientific benchmarks show that you could scale on Amazon EC2 to 50000 1024-bit RSA private operations per second. More benchmarks will follow.

Is it secure?
-------------

Hopefully a bit more secure than storing your private key on Internet-facing machine. Private keys are stored on AcceSSL workers only, and servers connected to the Internet store only public key.
On the other hand the decrypted payload is transmitted in clear text over UDP between OpenSSL client and AcceSSL worker. For more secure setup you could consider physically separate network for AcceSSL traffic.

nginx example
-------------

Using Ubuntu 14.04 as base platform:

* install nginx and AcceSSL on Web-server

  ```
  sudo apt-get install nginx
  sudo dpkg -i accessl_0.1_amd64.deb
  ```

* install AcceSSL on another machine that will act as a worker

  ```
  sudo dpkg -i accessl_0.1_amd64.deb
  ```

* obtain SSL keys

  For the rest of tutorial I'll assume you have public key `server.crt` on Web-server machine and private key in `server.key`.

* run twice as many workers as there cores on AcceSSL machine

  ```
  worker -p 10000 -k server.key &
  worker -p 10001 -k server.key &
  ...
  worker -p 1000N -k server.key &
  ```

* run `accessld` on Web-server machine specifying all the workers

  ```
  sudo accessld -w WORKER_IP:10000 -w WORKER_IP:10001 ... -w WORKER_IP:1000N &
  ```

* convert your `server.crt` into a stub-key, that can be loaded by nginx:

  ```
  crt2key server.crt server.stubkey
  ```

* configure nginx to use AcceSSL

  add
  ```
  ssl_engine accessl;
  ```
  to `/etc/nginx/nginx.conf` in global section (outside any `{}`)


* restart nginx

  ```
  sudo service nginx restart
  ```

Supported platforms
-------------------

Linux 64-bit. Currently tested only on Ubuntu 14.04. Should be able to compile on Mac OS X 10.9

TODO
----

Quite a lot actually. See Issues to see what is currently pending.

License
-------

[Affero GPL][AGPL]. Contact me if you'd like another license.


[HSM]: http://en.wikipedia.org/wiki/Hardware_security_module
[AGPL]: http://www.gnu.org/licenses/agpl-3.0.html
[engine]: https://www.openssl.org/docs/crypto/engine.html

