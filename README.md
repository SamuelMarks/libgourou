Introduction
------------

libgourou is a free implementation of Adobe's ADEPT protocol used to add DRM on ePub/PDF files. It overcome the lacks of Adobe support for Linux platforms.


Architecture
------------

Like RMSDK, libgourou has a client/server scheme. All platform specific functions (crypto, network...) has to be implemented in a client class (that derives from DRMProcessorClient) while server implements ADEPT protocol.
A reference implementation using Qt, OpenSSL and libzip is provided (in _utils_ directory).

Main fucntions to use from gourou::DRMProcessor are :

  * Get an ePub from an ACSM file : _fulfill()_ and _download()_
  * Create a new device : _createDRMProcessor()_
  * Register a new device : _signIn()_ and _activateDevice()_
  * Remove DRM : _removeDRM()_
  * Return loaned book : _returnLoan()_

You can import configuration from (at least) :

  * Kobo device    : .adept/device.xml, .adept/devicesalt  and .adept/activation.xml
  * Bookeen device : .adobe-digital-editions/device.xml, root/devkey.bin and .adobe-digital-editions/activation.xml
  
Or create a new one. Be careful : there is a limited number of devices that can be created bye one account.

ePub are encrypted using a shared key : one account / multiple devices, so you can create and register a device into your computer and read downloaded (and encrypted) ePub file with your eReader configured using the same AdobeID account.

For those who wants to remove DRM without adept_remove, you can export your private key and import it within [Calibre](https://calibre-ebook.com/) an its DeDRM plugin.


Dependencies
------------

For libgourou :

  * None

For utils :

  * libcurl
  * OpenSSL
  * libzip


Compilation
-----------

Use _make_ command

    make [CROSS=XXX] [DEBUG=(0*|1)] [STATIC_UTILS=(0*|1)] [BUILD_UTILS=(0|1*)] [BUILD_STATIC=(0*|1)] [BUILD_SHARED=(0|1*)]

CROSS can define a cross compiler prefix (ie arm-linux-gnueabihf-)

DEBUG can be set to compile in DEBUG mode

BUILD_UTILS to build utils or not

STATIC_UTILS to build utils with static library (libgourou.a) instead of default dynamic one (libgourou.so)

BUILD_STATIC build libgourou.a if 1, nothing if 0, can be combined with BUILD_SHARED

BUILD_SHARED build libgourou.so if 1, nothing if 0, can be combined with BUILD_STATIC

* Default value


Utils
-----

You can import configuration from your eReader or create a new one with _utils/adept\_activate_ :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/adept_activate -u <AdobeID USERNAME>

Then a _./.adept_ directory is created with all configuration file

To download an ePub/PDF :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/acsmdownloader -f <ACSM_FILE>

To export your private key (for DeDRM software) :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/acsmdownloader --export-private-key [-o adobekey_1.der]

To remove ADEPT DRM :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/adept_remove -f <encryptedFile>

To list loaned books :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/adept_loan_mgt [-l]

To return a loaned book :

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
    ./utils/adept_loan_mgt -r <id>

You can get utils full options description with -h or --help switch


Docker
------

A docker image (by bcliang) is available at [https://github.com/bcliang/docker-libgourou/](https://github.com/bcliang/docker-libgourou/)


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
  * _Milian_ for debug & code
