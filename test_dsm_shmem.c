#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/mman.h>

#define DEV_NAME "DSMmodule"
#define DSM_IOCTL_GETFD 0
#define DSM_IOCTL_FORCE_UPDATE 1

struct DSMpg{
    int dsmpg_id;
    int dsmpg_fd;
    int dsmpg_sz;
};

int main(int argc, char** argv){
    if(argc != 2){
        printf("%s [id]\n", argv[0]);
        return -1;
    }
    int mod;
    struct DSMpg dsmpg;
    char* ptr;
    dsmpg.dsmpg_id = atoi(argv[1]);
    dsmpg.dsmpg_fd = 0;
    dsmpg.dsmpg_sz = 4096;
    printf("dsmpg: %p\n", &dsmpg);
    printf("start open\n");
    if((mod = open("/dev/DSMmodule", O_RDONLY)) < 0)
        perror("open");
    printf("start ioctl\n");
    if((ioctl(mod, DSM_IOCTL_GETFD, &dsmpg)) < 0)
        perror("ioctl");
    // printf("dsmpg: %d %d %d\n", dsmpg.dsmpg_id, dsmpg.dsmpg_fd, dsmpg.dsmpg_sz);
    printf("fd: %d\n", dsmpg.dsmpg_fd);
    ptr = mmap(0, dsmpg.dsmpg_sz, PROT_READ|PROT_WRITE, MAP_SHARED, dsmpg.dsmpg_fd, 0);
    if(ptr == MAP_FAILED)
        perror("mmap");
    printf("print ptr: %p\n", ptr);
    char c;
    while(1){
        printf("(w:write, r:read, e:end): ");
        scanf("%c\n", &c);
        if(c == 'w')
            scanf("%d\n", (int*)ptr);
        else if(c == 'r')
            printf("ptr: %d\n", *((int*)ptr));
        else if(c == 'e')
            break;
    }
    // printf("start force update\n");
    // if(ioctl(mod, DSM_IOCTL_FORCE_UPDATE, &dsmpg) < 0)
    //     perror("ioctl");
    printf("start close\n");
    close(dsmpg.dsmpg_fd);
    close(mod);

    return 0;
}