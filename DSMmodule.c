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
#include <linux/highmem.h>
#include <linux/pagemap.h>

//소켓
#include <linux/net.h>
#include <linux/in.h>

//스레드
#include <linux/kthread.h>


#define DEV_NAME "DSMmodule"
#define DSM_TMP_DIR "/tmp/DSM"
#define DSM_IOCTL_GETFD 0
#define DSM_IOCTL_FORCE_UPDATE 1

#define DSM_MAX_PAGE_NUM 32

static enum msg_type{
    DSM_NEW_PG = 0,
    DSM_UPDATE_PG,
    DSM_REMOVE_PG,
    DSM_REQUEST_PG
};

//모듈 프로그래밍 참고용
//가이드
//https://sysprog21.github.io/lkmpg/
//각종 함수나 구조체를 커널 소스코드에서 찾아줌
//https://elixir.bootlin.com/linux/latest/source/include/linux/
//https://stackoverflow.com/questions/10441392/major-page-fault-handler-in-linux-kernel
//커스텀 mmap설정, 커스텀 fault설정
//https://pr0gr4m.tistory.com/entry/Linux-Kernel-5-mmap

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

struct msg_header{
    enum msg_type type;
    int id;
};

static struct DSMpg_info* find(int input_id);
static struct DSMpg_info* insert(int input_id, unsigned int input_sz);
static int remove(int input_id);

static int new_map_fd_install(struct DSMpg* dsmpg);
static int new_map_file(const char* buf, struct DSMpg_info* node);
static struct file* new_map_filp(const char* buf, struct DSMpg_info* node);

static int dsm_srv(int port);
static int dsm_connect(const char* ip, int port);
static int dsm_recv_thread(void* arg);

static int dsm_msg_new_pg(int id);
static int dsm_msg_update_pg(struct DSMpg_info* dsmpg);
static int dsm_msg_request_pg(int id);

static int dsm_msg_handle_new_pg(int id);
static int dsm_msg_handle_update_pg(struct DSMpg_info* dsmpg, void* data);
static int dsm_msg_handle_request_pg(int id);

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
static struct task_struct* recv_thread = NULL;
char* dsm_ip_addr;
int dsm_port;
//페이지 정보 링크드 리스트
static struct DSMpg_info* head = NULL;
static int nodnum = 0;

//arguments
//charp: char*
module_param(dsm_ip_addr, charp, 0600);
module_param(dsm_port, int, 0600);

//ioctl로 open될 파일의 operations
// struct file_operations map_fops = {
//     .mmap = dsm_mmap
// };

//dsm_mmap으로 mmap될 vm_area_struct의 operations
// struct vm_operations_struct dsm_vma_ops = {
//     .fault = dsm_vma_fault
// };

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
        //링크드 리스트에 삽입
        node = insert(dsmpg->dsmpg_id, dsmpg->dsmpg_sz);
        ret = !node;
        if(ret){
            printk("insert failed %d\n", ret);
            return ret;
        }
        //새로운 페이지 생성 알림
        dsm_msg_new_pg(dsmpg->dsmpg_id);
        // //새로운 파일 생성
        // ret = new_map_file(buf, node);
        // if(ret){
        //     printk("new_map_file failed %d\n", ret);
        //     return ret;
        // }
    }

    //해당 파일포인터 얻기
    fp = new_map_filp(buf, node);
    ret = !fp;
    if(ret){
        printk("new_map_file failed %d\n", ret);
        return ret;
    }

    if(is_new){
        ret = vfs_truncate(&fp->f_path, 4096);
        if(ret){
            printk("vfs_truncate failed %d\n", ret);
            return ret;
        }
    }

    //유저에게 fd설정
    dsmpg->dsmpg_fd = get_unused_fd_flags(O_CLOEXEC);
    fd_install(dsmpg->dsmpg_fd, fp);

    return 0;
}

static int new_map_file(const char* buf, struct DSMpg_info* node){
    int ret;
    ret = kern_path(buf, LOOKUP_FOLLOW, &(node->path));
    if(ret){
        printk("kern_path failed %d\n", ret);
        return ret;
    }
    
    ret = vfs_truncate(&(node->path), node->sz);
    if(ret){
        printk("vfs_truncate failed %d\n", ret);
        return ret;
    }

    return 0;
}

static struct file* new_map_filp(const char* buf, struct DSMpg_info* node){
    struct file* fp;

    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);

    if(IS_ERR(fp)){
        printk("open failed\n");
        return NULL;
    }

    return fp;
}

//커널 기능

//유저 기능 호출

static long int dsm_ioctl(struct file* fp, unsigned int cmd, unsigned long arg){

    int ret;
    // struct file* pgfp;
    // struct path path;
    struct DSMpg dsmpg;
    struct DSMpg_info* node;

    //유저의 arg로부터 입력값을 커널 메모리로 가져옴
    // printk("copy from user %p to kernel %p\n", (struct DSMpg*)arg, &dsmpg);
    ret = copy_from_user(&dsmpg, (struct DSMpg*)arg, sizeof(struct DSMpg));
    if(ret){
        printk("copy_from_user failed %d\n", ret);
        return ret;
    }

    // printk("ioctl cmd: %d\ndsmpg: id:%d fd:%d sz:%d\n", cmd, dsmpg.dsmpg_id, dsmpg.dsmpg_fd, dsmpg.dsmpg_sz);

    switch(cmd){
        case DSM_IOCTL_GETFD:
            ret = new_map_fd_install(&dsmpg);
            if(ret){
                printk("DSM_IOCTL_GETFD failed %d\n", ret);
                return ret;
            }
            //수정된 arg를 다시 유저 메모리에 입력
            ret = copy_to_user((struct DSMpg*)arg, &dsmpg, sizeof(struct DSMpg));
            if(ret){
                printk("copy_to_user failed %d\n", ret);
                return ret;
            }
        break;
        case DSM_IOCTL_FORCE_UPDATE:
            ret = node = find(dsmpg.dsmpg_id);
            if(!ret){
                printk("DSM_IOCTL_FORCE_UPDATE to non exist id %d\n");
                return -1;
            }
            ret = dsm_msg_update_pg(node);
            if(ret){
                printk("dsm_msg_update_msg failed %d\n", ret);
                return ret;
            }
        break;
    }

    return 0;
}

//va_area_struct 관련
/*
static vm_fault_t dsm_vma_fault(struct vm_fault* vmf){
    //fault 발생시(vm접근시) 발생할 일
    //물리 메모리에 접근하는 대신 peer_sock으로부터 데이터 받아오기
    //or peer로부터 페이지 정보를 받고 페이지 할당 후 반영?
    struct page* page;
    void* pg_ptr;
    uint offset;

    page = follow_page(vma, vma->address, FOLL_WRITE|FOLL_FORCE);

    //최종적으로 할당할 page를 리턴해야함
    return page;
}

static int dsm_mmap(struct file* file, struct vm_area_struct vma){
    //파일에 mmap수행시 일어날 일 정의
    vma->vm_ops = &dsm_vma_ops;
    //해당 페이지 쓰기불가, 페이지에 write을 시도할 때 마다 page_fault가 발생한다.
    vma->vm_flags &= ~VM_WRITE;
    vma->vm_flags |= VM_DENYWRITE;
}
*/
//소켓 통신

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
        printk("sock_create failed %d\n", ret);
        return ret;
    }
    
    memset(&my_addr, 0, sizeof(struct sockaddr_in));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(port);

    printk("dsm_srv try bind\n");
    ret = my_sock->ops->bind(my_sock, (struct sockaddr*)&my_addr, sizeof(my_addr));
    if(ret){
        printk("bind failed %d\n", ret);
        return ret;
    }

    printk("dsm_srv try listen\n");
    ret = my_sock->ops->listen(my_sock, 5);
    if(ret){
        printk("listen failed %d\n", ret);
        return ret;
    }

    printk("dsm_srv try sock_create (peer)\n");
	ret = sock_create(AF_INET, SOCK_STREAM, 0, &peer_sock);
	if (ret){
        printk("sock_create failed %d\n", ret);
        return ret;
    }

    printk("dsm_srv try accept(%p, %p, 0, true)\n", my_sock, peer_sock);
    ret = my_sock->ops->accept(my_sock, peer_sock, 0, true);
    if(ret){
        printk("accept failed %d\n", ret);
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
        printk("sock_create failed %d\n", ret);
        return ret;
    }

    memset(&peer_addr, 0, sizeof(struct sockaddr_in));
    peer_addr.sin_family = AF_INET;
    //ip address parsing
    sscanf(ip, "%hhd.%hhd.%hhd.%hhd", &(ip_bytes[3]), &(ip_bytes[2]), &(ip_bytes[1]), &(ip_bytes[0]));
    printk("parsing %s to %u\n", dsm_ip_addr, *((unsigned int*)ip_bytes));
    peer_addr.sin_addr.s_addr = htonl(*((unsigned int*)ip_bytes));
    peer_addr.sin_port = htons(port);

    printk("try connect(%p, %p, %ld, 0)\n", peer_sock, &peer_addr, sizeof(struct sockaddr));
    ret = peer_sock->ops->connect(peer_sock, (struct sockaddr*)&peer_addr, sizeof(struct sockaddr), 0);
    if(ret){
        printk("connect failed %d\n", ret);
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

//통신 스레드 관련

static int dsm_recv_thread(void* arg){
    struct msghdr msg;
    struct kvec iv;
    struct msg_header header;
    struct DSMpg_info* dsmpg;
    void* buf;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    while(1){
        iv.iov_base = &header;
        iv.iov_len = sizeof(header);
        kernel_recvmsg(peer_sock, &msg, &iv, 1, iv.iov_len, 0);
        switch(header.type){
            case DSM_NEW_PG:
                dsm_msg_handle_new_pg(header.id);
            break;
            case DSM_UPDATE_PG:
                dsmpg = find(header.id);
                if(!dsmpg){
                    printk("DSM_UPDATE_PG to non exist id %d, ignored\n", header.id);
                    break;
                }
                buf = kvmalloc(dsmpg->sz, GFP_KERNEL);
                if(IS_ERR(buf)){
                    printk("kvmalloc failed\n");
                    break;
                }
                dsm_msg_handle_update_pg(dsmpg, buf);
            break;
            case DSM_REQUEST_PG:
                if(!find(header.id)){
                    printk("DSM_REQUSET_PG to non exist id %d, ignored\n", header.id);
                    break;   
                }
                dsm_msg_handle_request_pg(header.id);
            break;
        }
    }

    return -1;
}

//메시지 send관련

static int dsm_msg_new_pg(int id){
    struct msghdr msg;
    struct kvec iv;
    struct msg_header header;
    uint offset = 0;

    header.type = DSM_NEW_PG;
    header.id = id;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = &header;
    iv.iov_len = sizeof(header);
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);

    return 0;
}

static int dsm_msg_update_pg(struct DSMpg_info* dsmpg){
    struct file* fp;
    char buf[64];
    void* msg_buf;
    struct msghdr msg;
    struct kvec iv;
    uint offset = 0;
    
    msg_buf = kvmalloc(sizeof(DSM_UPDATE_PG)+sizeof(dsmpg->id)+dsmpg->sz, GFP_KERNEL);
    if(IS_ERR(msg_buf)){
        printk("kvmalloc failed\n");
        return -1;
    }
    ((struct msg_header*)msg_buf)->type = DSM_UPDATE_PG;
    ((struct msg_header*)msg_buf)->id = dsmpg->id;
    offset += sizeof(struct msg_header);

    //업데이트할 파일 열기
    sprintf(buf, "/dev/shm/DSM%d", dsmpg->id);
    fp = new_map_filp(buf, dsmpg);
    if(!fp){
        printk("new_map_filp failed\n");
        kvfree(msg_buf);
        return -1;
    }

    if(kernel_read(fp, msg_buf+offset, dsmpg->sz, &(fp->f_pos)) < 0){
        printk("kernel_read failed\n");
        kvfree(msg_buf);
        return -1;
    }
    offset += dsmpg->sz;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = msg_buf;
    iv.iov_len = offset;
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);

    kvfree(msg_buf);
    filp_close(fp, NULL);
    return 0;
}

static int dsm_msg_request_pg(int id){
    struct msghdr msg;
    struct kvec iv;
    struct msg_header header;
    uint offset = 0;

    header.type = DSM_REQUEST_PG;
    header.id = id;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = &header;
    iv.iov_len = sizeof(header);
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);
    return 0;
}

//메시지 recv관련

static int dsm_msg_handle_new_pg(int id){
    struct DSMpg_info* dsmpg = find(id);
    char buf[64];
    sprintf(buf, "/dev/shm/DSM%d", dsmpg->id);
    if(!dsmpg){
        printk("accepted new_pg but id already exist\n");
        return -1;
    }
    if(new_map_file(buf, dsmpg)){
        printk("new_map_fd_install failed\n");
        return -1;
    }

    return 0;
}

static int dsm_msg_handle_update_pg(struct DSMpg_info* dsmpg, void* data){
    struct file* fp;
    struct page* pg;
    char buf[64];

    //업데이트할 파일 열기
    sprintf(buf, "/dev/shm/DSM%d", dsmpg->id);
    fp = new_map_filp(data, dsmpg);
    if(IS_ERR(fp)){
        printk("new_map_file failed\n");
        return -1;
    }
    pg = find_lock_page(fp->f_mapping, 0);
    if(!pg){
        printk("find_lock_page failed\n");
        return -1;
    }

    memcpy(kmap(pg), data, dsmpg->sz);
    kunmap(pg);
    filp_close(fp, NULL);
    return 0;
}

static int dsm_msg_handle_request_pg(int id){
    struct DSMpg_info* dsmpg = find(id);
    return dsm_msg_update_pg(dsmpg);
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

    printk("DSM init recv_thread\n");
    err = recv_thread = kthread_run(dsm_recv_thread, NULL, "dsm_recv_thread");
    if(IS_ERR(recv_thread)){
        printk("kthread_tun failed\n");
        goto failed;
    }
    printk("DSM init recv_thread done\n");

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
    kthread_stop(recv_thread);
    printk("DSM exit!\n");
}

module_init(dsm_init);
module_exit(dsm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yun-Hui-Jun");
MODULE_DESCRIPTION("Module for Distibuted shared memory");