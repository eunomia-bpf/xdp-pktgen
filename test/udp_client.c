#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9876
#define SERVER_IP "127.0.0.1"
#define NUM_PACKETS 100000000

int main() {
    int sockfd;
    struct sockaddr_in serverAddr;
    char message[] = "Hello Server!";

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Send packets
    for (int i = 0; i < NUM_PACKETS; i++) {
        // printf("Sending packet %d\n", i + 1);
        if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
            perror("Send failed");
            break;
        }
    }

    close(sockfd);
    return 0;
}
