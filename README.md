# Fast Port Scanner

A multithreaded TCP port scanner for Windows, written in C++ with the Windows Sockets API (Winsock).

I built it to learn networking and concurrency. The first version was simple: 100 threads, each with its own slice of ports and a normal blocking `connect()`. It worked on hosts that answer, but on a firewalled host every port waited for the operating system's own timeout, about 21 seconds. This version puts a time limit on every connection attempt.

## What it does

- Scans a range of TCP ports on an IPv4 address or host name
- Uses a full TCP connect (the normal three-way handshake), so it needs no administrator rights
- Limits every attempt with a timeout (default 500 ms)
- Shares the work through one counter, so threads stay busy even when some ports are slow
- Prints open ports as they are found, then a sorted summary with common service names

## Measured

20 ports on an address that never answers (`192.0.2.1`, reserved for documentation), same computer:

| Version | Time |
|---|---|
| First version (blocking connect) | 21.84 s |
| This version (`--timeout 300`) | 0.32 s |

On a host that answers quickly both versions are fast; the difference is in what happens when nothing answers.

## Build

Requirements: Windows and a C++17 compiler.

```bat
g++ -std=c++17 -O2 -Wall -Wextra main.cpp -o scanner.exe -lws2_32
```

With Visual Studio the Winsock library is linked automatically.

## Usage

```text
scanner <host> <first-port> <last-port> [--threads N] [--timeout MS]
```

| Option | Meaning | Default |
|---|---|---|
| `--threads` | parallel connections, 1-1000 | 100 |
| `--timeout` | wait per port in milliseconds, 50-10000 | 500 |

Run it without arguments to be asked for the host and the ports.

Example:

```text
> scanner 127.0.0.1 1 1024
Scanning 127.0.0.1 (127.0.0.1), ports 1-1024, 100 threads, 500 ms timeout
[+] Port 135 is OPEN
[+] Port 445 is OPEN

Open ports:
  135/tcp  msrpc
  445/tcp  microsoft-ds

Scanned 1024 ports in 5.59 s: 2 open, 1 refused, 1021 no answer within 500 ms
```

## How it works

1. The host name is resolved once with `getaddrinfo`.
2. Each thread takes the next port from a shared atomic counter.
3. For every port a non-blocking socket starts the connection and `select()` waits for the result, up to the timeout.
4. A writable socket means the handshake finished (open). An error means the port refused. No result in time means the packets were dropped.
5. Open ports are collected under a mutex and printed sorted at the end.

## Notes and limits

- Windows retries a refused connection for about two seconds before reporting it. With a shorter timeout, closed ports are counted under "no answer" instead of "refused". Open ports are not affected.
- IPv4 and TCP only. No UDP scan and no service detection: the service names come from a fixed table of well-known ports.
- A connect scan is visible in the logs of the target.

## Legal

For learning and for testing your own systems. Scan only hosts you own or have permission to test.
