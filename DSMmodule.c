#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

//디바이스
#include <linux/device.h>
#include <linux/cdev.h>

//파일시스템
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <asm/uaccess.h>

//메모리
#include <linux/mm.h>
#include <linux/sched.h>

//소켓
#include <linux/net.h>
#include <linux/in.h>


#define DEV_NAME "DSMmodule"
#define DSM_TMP_DIR "/tmp/DSM"
#define DSM_IOCTL_GETFD 0
#define DSM_IOCTL_GETMETA 1

#define DSM_MAX_PAGE_NUM 32

//모듈 프로그래밍 참고용
//가이드
//https://sysprog21.github.io/lkmpg/
//각종 함수나 구조체를 커널 소스코드에서 찾아줌
//https://elixir.bootlin.com/linux/latest/source/include/linux/

// 특정 페이지에 대한 각종 정보들, 사용자를 위한 정보도 포함
struct DSMpg{
    int dsmpg_id;
    int dsmpg_fd;
    unsigned int dsmpg_sz;
};

struct DSMpg_info{
    struct path path;
    struct DSMpg_info* next;
    int id;
    unsigned int sz;
};

static struct DSMpg_info* find(int input_id);
static struct DSMpg_info* insert(int input_id, unsigned int input_sz);
static int remove(int input_id);

static int new_map_fd_install(struct DSMpg* dsmpg);
static int new_map_file(const char* buf, struct DSMpg_info* node);
static struct file* new_map_filp(const char* buf, struct DSMpg_info* node, bool is_new);

//모듈 상태
static bool mod_ready = 0;
//디바이스
static dev_t dv_dv;
static struct cdev dv_cdv;
static struct class* dv_class = NULL;
//소켓통신
static struct sockaddr_in my_addr;
static struct sockaddr_in peer_addr;
static struct socket* my_sock = NULL;
static struct socket* peer_sock = NULL;
char* dsm_ip_addr;
int dsm_port;
//페이지 정보 링크드 리스트
static struct DSMpg_info* head = NULL;
static int nodnum = 0;

//arguments
//charp: char*
module_param(dsm_ip_addr, charp, 0600);
module_param(dsm_port, int, 0600);

//페이지 정보 링크드 리스트
static struct DSMpg_info* find(int input_id){
    struct DSMpg_info* node = head;
    if(!head || head->id == input_id)
        return head;
    while(node->next && node->next->id != input_id)
        node = node->next;
    return node->next;
}

static struct DSMpg_info* insert(int input_id, unsigned int input_sz){
    struct DSMpg_info* node = head;
    struct DSMpg_info* new = kvmalloc(sizeof(struct DSMpg_info), GFP_KERNEL);
    if(IS_ERR(new))
        return NULL;
    new->next = NULL;
    new->id = input_id;
    new->sz = input_sz;
    if(!head){
        head = new;
        if(IS_ERR(head)){
            printk("insert: kmalloc failed\n");
            kvfree(new);
            new = NULL;
        }
        return new;
    }

    while(node->next)
        node = node->next;

    if(IS_ERR(node->next)){
        printk("insert: kmalloc failed\n");
        kvfree(new);
        new = NULL;
    }
    if(new)
        nodnum++;
    return new;
}

static int remove(int input_id){
    struct DSMpg_info* node = head;
    if(!head)
        return -1;
    if(head->id == input_id){
        kvfree(head);
        nodnum--;
        return 0;
    }
    
    while(node->next && node->next->id != input_id)
        node = node->next;
    
    if(!(node->next))
        return -1;

    kvfree(node->next);
    nodnum--;
    return 0;
}

static int new_map_fd_install(struct DSMpg* dsmpg){
    struct DSMpg_info* node;
    struct file* fp;
    int ret, is_new;
    char buf[32];

    sprintf(buf, "/dev/shm/DSM%d", dsmpg->dsmpg_id);

    node = find(dsmpg->dsmpg_id);
    is_new = !node;
    if(is_new){
        node = insert(dsmpg->dsmpg_id, dsmpg->dsmpg_sz);
        ret = !node;
        if(ret){
            printk("insert failed\n");
            return ret;
        }

        ret = new_map_file(buf, node);
        if(ret){
            printk("new_map_file failed]n");
            return ret;
        }
    }

    fp = new_map_filp(buf, node, is_new);
    ret = !fp;
    if(ret){
        printk("new_map_file failed\n");
        return ret;
    }

    dsmpg->dsmpg_fd = get_unused_fd_flags(O_CLOEXEC);
    fd_install(dsmpg->dsmpg_fd, fp);

    return 0;
}

static int new_map_file(const char* buf, struct DSMpg_info* node){
    int ret;
    ret = kern_path(buf, LOOKUP_DOWN, &(node->path));
    if(ret){
        printk("kern_path failed\n");
        return ret;
    }
    
    ret = vfs_truncate(&(node->path), node->sz);
    if(ret){
        printk("vfs_truncate failed\n");
        return ret;
    }

    return 0;
}

static struct file* new_map_filp(const char* buf, struct DSMpg_info* node, bool is_new){
    struct file* fp;

    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);

    if(IS_ERR(fp)){
        printk("open failed\n");
        return NULL;
    }

    return fp;
}

//커널 기능

static long int dsm_ioctl(struct file* fp, unsigned int cmd, unsigned long arg){

    int ret;
    // struct file* pgfp;
    // struct path path;
    struct DSMpg dsmpg;

    //유저의 arg로부터 입력값을 커널 메모리로 가져옴
    printk("copy from user %p to kernel %p\n", (struct DSMpg*)arg, &dsmpg);
    ret = copy_from_user(&dsmpg, (struct DSMpg*)arg, sizeof(struct DSMpg));
    if(ret){
        printk("copy_from_user failed\n");
        return ret;
    }

    printk("ioctl cmd: %d\ndsmpg: id:%d fd:%d sz:%d\n", cmd, dsmpg.dsmpg_id, dsmpg.dsmpg_fd, dsmpg.dsmpg_sz);

    switch(cmd){
        case DSM_IOCTL_GETFD:
        ret = new_map_fd_install(&dsmpg);
        if(ret){
            printk("new_map failed\n");
            return ret;
        }
        //수정된 arg를 다시 유저 메모리에 입력
        ret = copy_to_user((struct DSMpg*)arg, &dsmpg, sizeof(struct DSMpg));
        if(ret){
            printk("copy_to_user failed\n");
            return ret;
        }
    }

    //정상적이면 도달 안함
    return -1;
}

static int dsm_srv(int port){
    //원본 커널 소스코드에서 발췌 (/net/socket.c)
	struct msghdr msg;
    struct kvec iv;
    struct DSMpg_info* node;
    int ret;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

    printk("dsm_srv try sock_create\n");
	ret = sock_create(AF_INET, SOCK_STREAM, 0, &my_sock);
	if (ret){
        printk("sock_create failed\n");
        return ret;
    }
    
    memset(&my_addr, 0, sizeof(struct sockaddr_in));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(port);

    printk("dsm_srv try bind\n");
    ret = my_sock->ops->bind(my_sock, (struct sockaddr*)&my_addr, sizeof(my_addr));
    if(ret){
        printk("bind failed\n");
        return ret;
    }

    printk("dsm_srv try listen\n");
    ret = my_sock->ops->listen(my_sock, 5);
    if(ret){
        printk("listen failed\n");
        return ret;
    }

    printk("dsm_srv try sock_create (peer)\n");
	ret = sock_create(AF_INET, SOCK_STREAM, 0, &peer_sock);
	if (ret){
        printk("sock_create failed\n");
        return ret;
    }

    printk("dsm_srv try accept(%p, %p, 0, true)\n", my_sock, peer_sock);
    ret = my_sock->ops->accept(my_sock, peer_sock, 0, true);
    if(ret){
        printk("accept failed\n");
        return ret;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = &nodnum;
    iv.iov_len = sizeof(nodnum);

    /*여기서 NULL pointer dereference 발생*/
    printk("try kernel_sendmsg(%p, %p, %p, 1, %ld)\n", peer_sock, &msg, &iv, iv.iov_len);
    printk("&msg->msg_iter: %p\n", &msg.msg_iter);
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);

    printk("dsm_srv start send nodes\n");
    node = head;
    while(node){
        iv.iov_base = node;
        iv.iov_len = sizeof(*node);

        kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);
        node = node->next;
    }

    printk("DSM mod ready\n");
    mod_ready = true;
    return 0;
}

static int dsm_connect(const char* ip, int port){
    struct msghdr msg;
    struct kvec iv;
    struct DSMpg_info node_buf;
    struct DSMpg_info* node;
    unsigned char ip_bytes[4];
    char buf[32];
    int ret, i;

    /* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

    printk("try sock_create\n");
    ret = sock_create(AF_INET, SOCK_STREAM, 0, &peer_sock);
	if (ret){
        printk("sock_create failed\n");
        return ret;
    }

    memset(&peer_addr, 0, sizeof(struct sockaddr_in));
    peer_addr.sin_family = AF_INET;
    //ip address parsing
    sscanf(ip, "%hhd.%hhd.%hhd.%hhd", &(ip_bytes[3]), &(ip_bytes[2]), &(ip_bytes[1]), &(ip_bytes[0]));
    printk("parsing %s to %ld\n", dsm_ip_addr, *((unsigned int*)ip_bytes));
    peer_addr.sin_addr.s_addr = htonl(*((unsigned int*)ip_bytes));
    peer_addr.sin_port = htons(port);

    printk("try connect(%p, %p, %ld, 0)\n", peer_sock, &peer_addr, sizeof(struct sockaddr));
    ret = peer_sock->ops->connect(peer_sock, (struct sockaddr*)&peer_addr, sizeof(struct sockaddr), 0);
    if(ret){
        printk("connect failed\n");
        return ret;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = &nodnum;
    iv.iov_len = sizeof(nodnum);
    kernel_recvmsg(peer_sock, &msg, &iv, 1, iv.iov_len, 0);

    iv.iov_base = &node_buf;
    iv.iov_len = sizeof(node_buf);

    // kernel_recvmsg(peer_sock, &msg, &iv, 1, /*크기*/, /*flags*/);
    printk("start recv %d msg\n", nodnum);
    for(i = 0; i < nodnum; i++){
        kernel_recvmsg(peer_sock, &msg, &iv, 1, iv.iov_len, 0);
        printk("recved (id:%d, sz:%d)", node_buf.id, node_buf.sz);
        /*loop 종료 조건*/
        node = insert(node_buf.id, node_buf.sz);
        sprintf(buf, "/dev/shm/DSM%d", node_buf.id);
        new_map_file(buf, node);
    }

    printk("DSM mod ready\n");
    mod_ready = true;
    return 0;
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = dsm_ioctl
};

static int __init dsm_init(void)
{
    //변수+초기화
    int err = 0;
    struct path path;
    bool dv_dst, cl_dst, cdv_dst, ureg;

    printk("DSM init start\n");

    memset(&path, 0, sizeof(path));
    dv_dst = cl_dst = cdv_dst = ureg = 0;

    //디바이스 파일 생성
    //register_chrdev(DEV_MAJOR, DEV_NAME, &fops);

    if((err = alloc_chrdev_region(&dv_dv, 0, 1, DEV_NAME)))
        goto failed;
    ureg = 1;
    
    cdev_init(&dv_cdv, &fops);
    dv_cdv.owner = THIS_MODULE;

    if((err = cdev_add(&dv_cdv, dv_dv, 1)))
        goto failed;
    cdv_dst = 1;
    
    dv_class = class_create(THIS_MODULE, DEV_NAME);
    if((err = IS_ERR(dv_class)))
        goto failed;
    cl_dst = 1;
    
    device_create(dv_class, NULL, dv_dv, NULL, DEV_NAME);
    dv_dst = 1;

    printk("DSM init device setting done\n");

    printk("DSM init socket params:\ndsm_ip_addr: %s\ndsm_port: %d\n", dsm_ip_addr, dsm_port);
    //connect or bind
    //srv bind
    if(!strcmp(dsm_ip_addr, "127.0.0.1") || !strcmp(dsm_ip_addr, "localhost")){
        printk("try dsm_srv\n");
        err = dsm_srv(dsm_port);
        printk("dsm_srv returned %d\n", err);
        if(unlikely(err))
            goto failed;
    }
    else{
        printk("try dsm_connect\n");
        err = dsm_connect(dsm_ip_addr, dsm_port);
        printk("dsm_connect returned %d\n", err);
        if(unlikely(err))
            goto failed;
    }

    printk("DSM init socket done\n");

    printk("DSM init done\n");

    return 0;
failed:
    if(dv_dst)
        device_destroy(dv_class, dv_dv);
    if(cl_dst)
        class_destroy(dv_class);
    if(cdv_dst)
        cdev_del(&dv_cdv);
    if(ureg)
        unregister_chrdev_region(dv_dv, 1);    
    printk("DSM init failed with err %d\n", err);
    return -1;
}

static void __exit dsm_exit(void)
{
    device_destroy(dv_class, dv_dv);
    class_destroy(dv_class);
    cdev_del(&dv_cdv);
    unregister_chrdev_region(dv_dv, 1);
    printk("DSM exit!\n");
}

module_init(dsm_init);
module_exit(dsm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yun-Hui-Jun");
MODULE_DESCRIPTION("Module for Distibuted shared memory");