SVSOCKS - SOCKS5 server
==========================

svsocks is a lightweight and fast SOCKS5 server.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [License](#license)

## Features

- IPv4 & IPv6 dual-stack server
- Thread pool for accepting connections
- Non-blocking sockets with edge-triggered polling (epoll)
- CONNECT command
- Username/Password authentication
- IPv4, IPv6 and Domain Name address types
- Syslog logging

## Installation

- Clone the repository from [GitHub][] or [GitLab][]:

```console
git clone https://github.com/fksvs/svsocks
git clone https://gitlab.com/fksvs/svsocks
```

- change directory to `svsocks`:

```console
cd svsocks/
```
- build the source:

```console
make
```

## Usage

```console
usage: ./svsocks [options]
```

#### Options:
- -a, [listen address] : Set the listen address for incoming connections in IPv6 format.
- -p, [listen port] : Set the listen port for incoming connections.
- -n, [number of threads]: Set the number of threads to be used in the thread pool.
- -u, [username] : Set username for username/password authentication.
- -s, [password] : Set password for username/password authentication.

Default values can be changed in the source code as defined by macros.

## License

This project is free software; you can redistribute it and/or modify it under the terms of the GPLv3 license. See [LICENSE][] for details.

[GitHub]: https://github.com/fksvs/svsocks
[GitLab]: https://gitlab.com/fksvs/svsocks
[LICENSE]: https://www.gnu.org/licenses/gpl-3.0.en.html
