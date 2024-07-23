SVSOCKS - SOCKS5 server
==========================

**svsocks** is a lightweight and fast SOCKS5 server.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Contributing](#contributing)
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
- `-6`: Use IPv6 protocol.
- `-a [listen address]` : Specify the address for incoming connections.  (Use the appropriate address format.)
- `-p [listen port]` : Specify the port for incoming connections.
- `-n [number of threads]` : Specify the number of threads for the thread pool.
- `-u [username]` : Username for username/password authentication.
- `-P [password]`  : Password for username/password authentication.

#### Example

Start the server on a specific address and port with a custom number of threads:
```console
./svsocks -a 192.168.1.100 -p 5000 -n 1000
```

## Contributing

Pull requests are welcome. For bug fixes and small improvements, please submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is free software; you can redistribute it and/or modify it under the terms of the GPLv3 license. See [LICENSE][] for details.

[GitHub]: https://github.com/fksvs/svsocks
[GitLab]: https://gitlab.com/fksvs/svsocks
[LICENSE]: https://www.gnu.org/licenses/gpl-3.0.en.html
