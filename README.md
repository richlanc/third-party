## Building

This is a set of build containers for various packages, brought up to date for Xenial 64 bits.

- `make debs`: Create the debian packages.
- `ARTIFACTORY_USR=[user] ARTIFACTORY_PSW=[password] make upload`: Push them to artifactory.
