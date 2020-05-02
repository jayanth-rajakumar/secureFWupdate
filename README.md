# secureFWupdate
UCI EECS 245 Project - C++ implementation of secure firmware update protocol for emebdded systems

Original protocol description from https://ieeexplore.ieee.org/document/8966174

## Dependency - OpenSSL

**Ubuntu**: sudo apt install libssl-dev

**macOS**: https://medium.com/@timmykko/using-openssl-library-with-macos-sierra-7807cfd47892

## Compilation and usage

Compile with *make* and execute client and server executables parallelly.

    ./server <port>
    ./client <server-ip> <port>
