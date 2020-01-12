#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#define BUF_LENGTH 25
int main(){
    char chunk[25];
    char buffer[25];
    FILE * fp = fopen("config.txt", "r");
    if (!fp){
        perror("can not open file");
        return errno;
    }
    fgets(buffer,BUF_LENGTH, fp);
    sscanf(buffer,"%s", chunk);
    printf("Mode : %s\n",chunk);

    int fd = open("/dev/Mfirewall", O_RDWR);
    if (fd < 0){
        perror("can not open device");
        return errno;
    }
    int writer = write(fd, buffer, strlen(buffer));
    if (writer < 0){
        perror("send to device failed");
        return errno;
    }
    char buf[25];
    bzero(buffer,BUF_LENGTH);

    while(fgets(buffer,BUF_LENGTH, fp)){
        bzero(buf,BUF_LENGTH);
        strncpy(buf,buffer,strlen(buffer)-1);
        writer = write(fd, buffer, strlen(buffer));
        if (writer < 0){
            perror("send to device failed");
            return errno;
        }
        printf("%s send successfully to device\n",buf);
    }
    fclose(fp);
    return 0;
}
