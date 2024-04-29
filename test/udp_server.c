#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define PORT 9876
#define BUFFER_SIZE 1024

volatile int num_packets = 0;  // Global variable to track the number of packets

// Function to monitor packets per second
void *monitor_packets(void *arg) {
    while (1) {
        int current_count = num_packets;
        sleep(1);
        int new_count = num_packets;
        printf("Packets received in the last second: %d\n", new_count - current_count);
    }
    return NULL;
}

int main() {
    int sockfd;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_size;
    pthread_t thread_id;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind socket
    if (bind(sockfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    printf("UDP Server listening on port %d\n", PORT);

    // Start monitoring thread
    if (pthread_create(&thread_id, NULL, monitor_packets, NULL) != 0) {
        perror("Failed to create thread");
        exit(EXIT_FAILURE);
    }

    while (1) {
        addr_size = sizeof(clientAddr);
        // Receive packets
        if (recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddr, &addr_size) < 0) {
            perror("Receive failed");
        } else {
            num_packets++;
        }
    }

    return 0;
}
