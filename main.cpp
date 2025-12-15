#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <winsock2.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>

// Link the Winsock library
#pragma comment(lib, "ws2_32.lib")

using namespace std;

// Mutex to stop threads from writing to console at the same time
mutex print_mtx;

// The function that each thread will run
void scan(string ip, int start_p, int end_p) {
    for (int p = start_p; p <= end_p; p++) {
        
        // Create TCP socket
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) continue;

        // Setup address structure
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(p);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());

        // Try to connect. If 0, connection accepted
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            
            // Lock console before printing
            lock_guard<mutex> lock(print_mtx);
            cout << "[+] Port " << p << " is OPEN" << endl;
        }

        // Always close socket!
        closesocket(s);
    }
}

int main() {
    // Init Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "Winsock init failed." << endl;
        return 1;
    }

    string ip;
    int start, end;
    int thread_count = 100; // Number of parallel threads

    cout << "--- FAST PORT SCANNER (Multithreaded) ---" << endl;
    cout << "Target IP: ";
    cin >> ip;
    cout << "Start Port: ";
    cin >> start;
    cout << "End Port: ";
    cin >> end;

    cout << "\nScanning " << ip << " with " << thread_count << " threads...\n";

    vector<thread> threads;
    int total_ports = end - start + 1;
    
    // Calculate how many ports each thread handles
    int range = total_ports / thread_count;
    if (range == 0) range = 1; 

    int current_p = start;

    // Spawn threads
    for (int i = 0; i < thread_count; i++) {
        int end_p = current_p + range - 1;
        
        // Handle the last thread range
        if (i == thread_count - 1) {
            end_p = end; 
        }

        if (current_p > end) break;

        // Launch thread
        threads.emplace_back(scan, ip, current_p, end_p);
        
        current_p = end_p + 1;
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    WSACleanup();
    cout << "Done." << endl;
    
    system("pause");
    return 0;
}