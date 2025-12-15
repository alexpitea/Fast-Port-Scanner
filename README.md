# Fast-Port-Scanner
A high-performance multithreaded TCP port scanner built in C++ using the Windows Sockets API (Winsock).
I built this project to learn more about networking and concurrency. My first version was single-threaded and waited too long for timeouts on firewalled ports. To fix this, I rewrote the logic to use Multithreading (std::thread), which makes it much faster by scanning ~100 ports in parallel.

How it works
The program takes a target IP and a port range (e.g., 1-1000).

It calculates how to split the work evenly across 100 threads.

I used a mutex to lock the console output so the threads don't write over each other.

It uses the standard TCP 3-way handshake to check if a port is open.

Usage
Compile it using G++ (MinGW) or Visual Studio. Make sure to link the ws2_32 library.

Command line:

Bash

g++ main.cpp -o scanner -lws2_32
./scanner
Then just follow the inputs on the screen:

Target IP (use 127.0.0.1 for local testing)

Start Port

End Port

Note: This is for educational purposes only.
