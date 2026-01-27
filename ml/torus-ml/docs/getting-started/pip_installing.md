# Installation

This document provides guides on how to install Torus ML using PyPi or Docker.

## Prerequisite

Before you start, determine your environment:

- Hardware platform
- Operating System (OS) version
- Python version

### OS/HW support

Depending on your OS/HW, Torus ML may be installed with Docker or with pip:

|                 OS / HW                 | Available on Docker | Available on pip |
| :-------------------------------------: | :-----------------: | :--------------: |
|                  Linux                  |         Yes         |       Yes        |
|                 Windows                 |         Yes         |        No        |
|       Windows Subsystem for Linux       |         Yes         |       Yes        |
|            macOS 11+ (Intel)            |         Yes         |       Yes        |
| macOS 11+ (Apple Silicon: M1, M2, etc.) |     Coming soon     |       Yes        |

### Python support

- **Version**: In the current release, Torus ML supports only `3.8`, `3.9`, `3.10`, `3.11` and `3.12` versions of `python`.
- **Linux requirement**: The Torus ML Python package requires `glibc >= 2.28`. On Linux, you can check your `glibc` version by running `ldd --version`.
- **Kaggle installation**: Torus ML can be installed on Kaggle ([see question on community for more details](https://community.luxfhe.io/t/how-do-we-use-torus-ml-on-kaggle/332)) and on Google Colab.

Most of these limits are shared with the rest of the Concrete stack (namely Concrete Python). Support for more platforms will be added in the future.

## Installation using PyPi

### Requirements

Installing Torus ML using PyPi requires a Linux-based OS or macOS (both x86 and Apple Silicon CPUs are supported).

{% hint style="info" %} If you need to install on Windows, use Docker or WSL. On WSL, Torus ML will work as long as the package is not installed in the `/mnt/c/` directory, which corresponds to the host OS filesystem. {% endhint %}

### Installation

To install Torus ML from PyPi, run the following:

```shell
pip install -U pip wheel setuptools
pip install torus-ml
```

This will automatically install all dependencies, notably Concrete.

If you encounter any issue during installation on Apple Silicon mac, please visit this [troubleshooting guide on community](https://community.luxfhe.io/t/troubleshooting-concrete-installation-on-apple-silicon/577).

## Installation using Docker

You can install Torus ML using Docker by either pulling the latest image or a specific version:

```shell
docker pull luxfhefhe/torus-ml:latest
# or
docker pull luxfhefhe/torus-ml:v0.4.0
```

You can use the image with Docker volumes, [see the Docker documentation here](https://docs.docker.com/storage/volumes/). Use the following command:

```shell
# Without local volume:
docker run --rm -it -p 8888:8888 luxfhefhe/torus-ml

# With local volume to save notebooks on host:
docker run --rm -it -p 8888:8888 -v /host/path:/data luxfhefhe/torus-ml
```

This will launch a Torus ML enabled Jupyter server in Docker that can be accessed directly from a browser.

Alternatively, you can launch a shell in Docker, with or without volumes:

```shell
docker run --rm -it luxfhefhe/torus-ml /bin/bash
```
