Introduction
------------

libgourou is a free implementation of Adobe's ADEPT protocol used to add DRM on ePub files. It overcome the lacks of Adobe support for Linux platforms.



Dependencies
------------

For libgourou :

  * None

For utils :

  * QT5Core
  * QT5Network
  * OpenSSL
  * libzip



Utils
-----

You can import configuration from your eReader or create a new one with activate :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./activate -u <AdobeID USERNAME>

Then a _./.adept_ directory is created with all configuration file

To download an ePub :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./acsmdownloader -f <ACSM_FILE>



Sources
-------

http://indefero.soutade.fr/p/libgourou



Copyright
---------

Grégory Soutadé



License
-------

libgourou : LGPL v3 or later

utils     : BSD



Special thanks
--------------

  * _Jens_ for all test samples and utils testing
  