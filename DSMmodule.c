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
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>

//소켓
#include <linux/net.h>
#include <linux/in.h>

//스레드
#include <linux/kthread.h>


#define DEV_NAME "DSMmodule"
#define DSM_TMP_DIR "/tmp/DSM"
#define DSM_IOCTL_GETFD 0
#define DSM_IOCTL_FORCE_UPDATE 1
#define DSM_IOCTL_GET_UPDATE 2

#define DSM_MAX_PAGE_NUM 32

static enum msg_type{
    DSM_NEW_PG = 0,
    DSM_UPDATE_PG,
    DSM_UPDATE_PG2, //페이지 전체를 전송하지 않고 수정할 부분만 전송
    DSM_REMOVE_PG,
    DSM_REQUEST_PG,
    DSM_FINISH
};

/*

*/

//모듈 프로그래밍 참고용
//가이드
//https://sysprog21.github.io/lkmpg/
//각종 함수나 구조체를 커널 소스코드에서 찾아줌
//https://elixir.bootlin.com/linux/latest/source/include/linux/
//https://stackoverflow.com/questions/10441392/major-page-fault-handler-in-linux-kernel
//커스텀 mmap설정, 커스텀 fault설정
//https://pr0gr4m.tistory.com/entry/Linux-Kernel-5-mmap
//address space구조체 설명
//https://hooneyo.tistory.com/entry/%ED%8E%98%EC%9D%B4%EC%A7%80-%EC%BA%90%EC%8B%9C

// 특정 페이지에 대해 ioctl등으로 사용자와 통신시 사용하는 구조체
struct DSMpg{
    int dsmpg_id;
    int dsmpg_fd;
    unsigned int dsmpg_sz;
};

// 모듈에서 참조하는 링크드 리스트
struct DSMpg_info{
    struct DSMpg_info* next;
    struct inode* inode;
    int id;
    unsigned int sz;
};

// 메시지 헤더
struct msg_header{
    enum msg_type type; //msg type
    int id; //pg id
    unsigned int sz; //pg size
};

//함수 선언
static struct DSMpg_info* list_find(int input_id);
static struct DSMpg_info* list_find_by_inode(const struct inode* inode);
static struct DSMpg_info* list_insert(int input_id, unsigned int input_sz, struct file* fp);
static int list_remove(int input_id);
static int list_reset(void);

static int new_map_fd_install(struct DSMpg* dsmpg);
static struct DSMpg_info* new_map_file(int id, unsigned int sz);

static int dsm_srv(int port);
static int dsm_connect(const char* ip, int port);
static int dsm_recv_thread(void* arg);

static int dsm_msg_new_pg(int id, unsigned int sz);
static int dsm_msg_update_pg(struct DSMpg_info* dsmpg);
static int dsm_msg_request_pg(int id);
static void dsm_msg_finish(void);

static int dsm_msg_handle_new_pg(int id, unsigned int sz);
static int dsm_msg_handle_update_pg(struct DSMpg_info* dsmpg, void* data);
static int dsm_msg_handle_request_pg(int id);
static void dsm_msg_handle_finish(void);

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
//args
char* dsm_ip_addr;
int dsm_port;
//페이지 정보 링크드 리스트
static struct DSMpg_info* head = NULL;
static int nodnum = 0;
//DSM mappage파일을 위한 a_ops
extern const struct address_space_operations shmem_aops;
static struct address_space_operations dsm_shmem_aops;

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

/*
특정 id의 노드 탐색, 없으면 NULL
*/
static struct DSMpg_info* list_find(int input_id){
    struct DSMpg_info* node = head;
    if(!head || head->id == input_id)
        return head;
    while(node->next && node->next->id != input_id)
        node = node->next;
    return node->next;
}

static struct DSMpg_info* list_find_by_inode(const struct inode* inode){
    struct DSMpg_info* node = head;
    if(!head || head->inode == inode)
        return head;
    while(node->next && node->next->inode != inode)
        node = node->next;
    return node->next;
}

/*
특정 id의 노드 입력하고 입력된 노드 리턴
사용 이전에 
*/
static struct DSMpg_info* list_insert(int input_id, unsigned int input_sz, struct file* fp){
    struct DSMpg_info* node = head;
    struct DSMpg_info* new = kvmalloc(sizeof(struct DSMpg_info), GFP_KERNEL);
    if(IS_ERR(new))
        return NULL;
    new->next = NULL;
    new->id = input_id;
    new->sz = input_sz;
    new->inode = fp->f_inode;
    if(!head){
        head = new;
        nodnum++;
        return new;
    }

    while(node->next)
        node = node->next;
    node->next = new;
    nodnum++;

    return new;
}

/*
특정 id의 노드 제거
*/
static int list_remove(int input_id){
    struct DSMpg_info* node = head;
    struct DSMpg_info* target;
    if(!head)
        return -1;
    if(head->id == input_id){
        kvfree(head);
        head = NULL;
        nodnum--;
        return 0;
    }
    
    while(node->next && node->next->id != input_id)
        node = node->next;
    target = node->next;
    
    if(!target)
        return -1;

    node->next = target->next;
    kvfree(target);
    nodnum--;
    return 0;
}

/*
링크드 리스트 완전초기화
*/
static int list_reset(void){
    struct DSMpg_info* next_head;
    while(head){
        next_head = head->next;
        kvfree(head);
        head = next_head;
    }
    nodnum = 0;
    return 0;
}

static int new_map_fd_install(struct DSMpg* dsmpg){
    struct DSMpg_info* node;
    struct file* fp;
    int ret, is_new;
    char buf[32];

    sprintf(buf, "/dev/shm/DSM%d", dsmpg->dsmpg_id);

    node = list_find(dsmpg->dsmpg_id);
    is_new = !node;
    if(is_new){
        //링크드 리스트에 삽입
        node = new_map_file(dsmpg->dsmpg_id, dsmpg->dsmpg_sz);
        if(!node){
            printk("insert failed %d\n", ret);
            return -1;
        }
        //새로운 페이지 생성 알림
        dsm_msg_new_pg(dsmpg->dsmpg_id, dsmpg->dsmpg_sz);
    }

    //해당 파일포인터 얻기
    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);
    if(IS_ERR(fp)){
        printk("filp_open failed\n");
        return -1;
    }

    //address_space의 a_ops를 커스텀 aops로 설정
    fp->f_mapping->a_ops = &dsm_shmem_aops;

    //유저에게 fd설정
    dsmpg->dsmpg_fd = get_unused_fd_flags(O_CLOEXEC);
    fd_install(dsmpg->dsmpg_fd, fp);

    return 0;
}

static struct DSMpg_info* new_map_file(int id, unsigned int sz){
    struct file* fp;
    char buf[32];
    struct DSMpg_info* ret;
    sprintf(buf, "/dev/shm/DSM%d", id);
    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);
    if(IS_ERR(fp)){
        printk("filp_open failed\n");
        return NULL;
    }
    if(vfs_truncate(&fp->f_path, sz)){
        printk("vfs_truncate failed\n");
        return NULL;
    }
    ret = list_insert(id, sz, fp);
    filp_close(fp, NULL);
    return ret;
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
            node = list_find(dsmpg.dsmpg_id);
            if(!node){
                printk("DSM_IOCTL_FORCE_UPDATE to non exist id %d\n", dsmpg.dsmpg_id);
                return -1;
            }
            ret = dsm_msg_update_pg(node);
            if(ret){
                printk("dsm_msg_update_pg failed %d\n", ret);
                return ret;
            }
        break;
        case DSM_IOCTL_GET_UPDATE:
            node = list_find(dsmpg.dsmpg_id);
            if(!node){
                printk("DSM_IOCTL_GET_UPDATE to non exist id %d\n", dsmpg.dsmpg_id);
                return -1;
            }
            ret = dsm_msg_request_pg(dsmpg.dsmpg_id);
            if(ret){
                printk("dsm_msg_request_pg failed %d\n", ret);
                return ret;
            }
            /*
            실제 업데이트 완료를 대기하는 코드?
            */
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
    unsigned int offset;

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
    unsigned char ip_bytes[4];
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
        new_map_file(node_buf.id, node_buf.sz);
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

    while(mod_ready){
        iv.iov_base = &header;
        iv.iov_len = sizeof(header);
        kernel_recvmsg(peer_sock, &msg, &iv, 1, iv.iov_len, 0);
        printk("handle msg id:%d, type:%d, sz:%d\n", header.id, header.type, header.sz);
        switch(header.type){
            case DSM_NEW_PG:
                if(list_find(header.id)){
                    printk("DSM_NEW_PG to exist id %d (find returned %p), ignored\n", header.id, list_find(header.id));
                    break;   
                }
                if(dsm_msg_handle_new_pg(header.id, header.sz)){
                    printk("dsm_msg_handle_new_pg failed, ignored\n");
                    break;
                }
            break;
            case DSM_UPDATE_PG:
                dsmpg = list_find(header.id);
                buf = kvmalloc(header.sz, GFP_KERNEL);
                if(IS_ERR(buf)){
                    printk("kvmalloc failed\n");
                    break;
                }
                iv.iov_base = buf;
                iv.iov_len = header.sz;
                kernel_recvmsg(peer_sock, &msg, &iv, 1, iv.iov_len, 0);
                if(!dsmpg)
                    printk("DSM_UPDATE_PG to non exist id %d, ignored\n", header.id);
                else
                    dsm_msg_handle_update_pg(dsmpg, buf);
                kvfree(buf);
            break;
            case DSM_REQUEST_PG:
                if(!list_find(header.id)){
                    printk("DSM_REQUSET_PG to non exist id %d, ignored\n", header.id);
                    break;   
                }
                dsm_msg_handle_request_pg(header.id);
            break;
            case DSM_REMOVE_PG:
            break;
            default:
                printk("unknown msg type\n");
            break;
        }
    }

    return -1;
}

//메시지 send관련

static int dsm_msg_new_pg(int id, unsigned int sz){
    struct msghdr msg;
    struct kvec iv;
    struct msg_header header;

    header.type = DSM_NEW_PG;
    header.id = id;
    header.sz = sz;

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
    unsigned int offset = 0;
    
    msg_buf = kvmalloc(sizeof(DSM_UPDATE_PG)+sizeof(dsmpg->id)+dsmpg->sz, GFP_KERNEL);
    if(IS_ERR(msg_buf)){
        printk("kvmalloc failed\n");
        return -1;
    }
    ((struct msg_header*)msg_buf)->type = DSM_UPDATE_PG;
    ((struct msg_header*)msg_buf)->id = dsmpg->id;
    ((struct msg_header*)msg_buf)->sz = dsmpg->sz;
    offset += sizeof(struct msg_header);

    //업데이트할 파일 열기
    sprintf(buf, "/dev/shm/DSM%d", dsmpg->id);
    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);
    if(!fp){
        printk("filp_open failed\n");
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

    header.type = DSM_REQUEST_PG;
    header.id = id;
    header.sz = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    iv.iov_base = &header;
    iv.iov_len = sizeof(header);
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);
    return 0;
}

static void dsm_msg_finish(void){
    struct msghdr msg;
    struct kvec iv;
    struct msg_header header;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)peer_sock;
    msg.msg_namelen = sizeof(*peer_sock);

    header.type = DSM_REQUEST_PG;
    header.id = 0;
    header.sz = 0;

    iv.iov_base = &header;
    iv.iov_len = sizeof(header);
    kernel_sendmsg(peer_sock, &msg, &iv, 1, iv.iov_len);
}

//메시지 recv관련

static int dsm_msg_handle_new_pg(int id, unsigned int sz){
    struct DSMpg_info* dsmpg;
    char buf[64];
    if(list_find(id)){
        printk("dms_msg_handle_new_pg id already exist %d\n", id);
        return -1;
    }
    sprintf(buf, "/dev/shm/DSM%d", id);
    dsmpg = new_map_file(id, sz);
    if(!dsmpg){
        printk("new_map_file failed\n");
        return -1;
    }

    return 0;
}

static int dsm_msg_handle_update_pg(struct DSMpg_info* dsmpg, void* data){
    struct file* fp;
    char buf[64];

    //업데이트할 파일 열기
    sprintf(buf, "/dev/shm/DSM%d", dsmpg->id);
    fp = filp_open(buf, O_CREAT|O_RDWR, 0600);
    if(IS_ERR(fp)){
        printk("filp_open failed\n");
        return -1;
    }
    vfs_write(fp, data, dsmpg->sz, fp->f_pos);
    filp_close(fp, NULL);
    return 0;
}

static int dsm_msg_handle_request_pg(int id){
    struct DSMpg_info* dsmpg = list_find(id);
    return dsm_msg_update_pg(dsmpg);
}

static void dsm_msg_handle_finish(void){
    list_reset();
}

static int dsm_shmem_writepage(struct page *page, struct writeback_control *wbc){
    struct folio *folio = page_folio(page);
	struct address_space *mapping = folio->mapping;
    struct inode *inode = mapping->host;
    struct DSMpg_info* dsmpg;
    void* va;
    /*
    DSMpg_info의 linked list를 조회하며 inode에 해당하는 파일의 노드 구하기
    해당 노드의 정보로 dsm_msg_update_pg 수행
    va에 kmap으로 매핑, 메시지 전송 후 kunmap
    */
    dsmpg = list_find_by_inode(inode);
    va = kmap(page);
    if(dsm_msg_update_pg(dsmpg))
        printk("from dsm_shmem_writepage, dsm_msg_update_pg failed\n");
    kunmap(page);
    return shmem_aops.writepage(page, wbc);
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

    //dsm_shmem_aops 설정
    printk("set dsm_shmem_aops\n");
    dsm_shmem_aops = shmem_aops;
    dsm_shmem_aops.writepage = dsm_shmem_writepage;

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
    recv_thread = kthread_run(dsm_recv_thread, NULL, "dsm_recv_thread");
    if(IS_ERR(recv_thread)){
        err = -1;
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
    int ret;
    //디바이스 관련 종료
    device_destroy(dv_class, dv_dv);
    class_destroy(dv_class);
    cdev_del(&dv_cdv);
    unregister_chrdev_region(dv_dv, 1);
    printk("remove device stop\n");
    //recv스레드 종료
    mod_ready = 0;
    kthread_stop(recv_thread);
    printk("recv_thread stop\n");
    //소켓 종료
    ret = peer_sock->ops->shutdown(peer_sock, 0);
    if(ret)
        printk("peer_sock shutdown failed\n");
    ret = my_sock->ops->shutdown(my_sock, 0);
    if(ret)
        printk("my_sock shutdown failed\n");
    printk("socket shutdown done\n");
    printk("DSM exit!\n");
}

module_init(dsm_init);
module_exit(dsm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yun-Hui-Jun");
MODULE_DESCRIPTION("Module for Distibuted shared memory");