#include <asm/atomic.h>
#include <linux/semaphore.h>
#include <net/net_namespace.h>
#include <net/netlink.h>

// 定义新的netlink协议类型，与用户态一致
#define NETLINK_SAFE 30

static struct sock* socket;
static int pid = 0;
static int ino_len = sizeof(unsigned long);
static atomic_t sequence = ATOMIC_INIT(0);

// 创建了一个队列，使用信号量保护
static struct queue {
    uid_t data[65536];
    struct semaphore sem[65536];
} rspbuf;

DEFINE_RATELIMIT_STATE(rs, 3 * HZ, 1);

/*
** Send inode number to user space daemon process via netlink, and wait for response (uid).
** Note we maintain atomic sequence number to synchronize netlink with response request,
** and use semaphore to synchronize buffer queue read operation with write operation.
** The above plus a large enough buffer queue will avoid race conditions.
*/
static uid_t get_owner(unsigned long inode) {
    // sk_buff是内核态存储网络数据的重要结构
    struct sk_buff* skb;
    struct nlmsghdr* nlh;
    unsigned short seq;

    /*
    ** If user space daemon process is not ready.
    */
    // TODO: 所以这里要注意启动的顺序
    if (!pid) {
        return 0;
    }

    // 创建 sk_buff空间
    skb = nlmsg_new(ino_len, GFP_ATOMIC);
    if (!skb) {
        return 0;
    }
    // 设置netlink消息头部
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, ino_len, 0);
    seq = atomic_inc_return(&sequence);
    nlh->nlmsg_seq = seq;
    *(unsigned long*)NLMSG_DATA(nlh) = inode;
    // 单播类型发送数据
    // 用户态使用pid作为标识符
    nlmsg_unicast(socket, skb, pid);
    /*
    ** Wait for at most 3s. Tested on Linux with 250 HZ timer interrupt frequency.
    */
    // 等待用户态返回的数据存入指定的位置
    // 检查信号量
    if (down_timeout(&rspbuf.sem[seq], 3 * HZ)) {
        if (__ratelimit(&rs)) {
            pid = 0;
            printk(KERN_NOTICE "[safe] Safe terminated!\n");
        }
        return 0;
    }

    return rspbuf.data[seq];
}

/*
** If daemon process is ready, this will receive owner uid;
** Otherwise this will receive a ready signal.
*/
static void nl_receive_callback(struct sk_buff* skb) {
    struct nlmsghdr* nlh = (struct nlmsghdr*)skb->data;

    if (*(unsigned long*)NLMSG_DATA(nlh) >> 32 != 0xffffffff) {
        // 将用户态回复的数据按照序列号存入对应的位置
        rspbuf.data[nlh->nlmsg_seq] = *(uid_t*)NLMSG_DATA(nlh);
        up(&rspbuf.sem[nlh->nlmsg_seq]);
    } else {
        // 接收到了ready signal
        // 提取服务器进程的pid
        if (NETLINK_CREDS(skb)->pid == nlh->nlmsg_pid && !NETLINK_CREDS(skb)->uid.val) {
            printk(KERN_NOTICE "[safe] Safe initiated!\n");
            pid = nlh->nlmsg_pid;
        }
    }
}

static int __init netlink_init(void) {
    // 设置接收到消息的回调函数
    struct netlink_kernel_cfg cfg = {
        .input = nl_receive_callback,
    };
    int i;
    // 创建内核态netlink套接字
    socket = netlink_kernel_create(&init_net, NETLINK_SAFE, &cfg);
    // 初始化消息队列
    for (i = 0; i < 65536; ++i) {
        rspbuf.data[i] = 0;
        sema_init(&rspbuf.sem[i], 0);
    }
    ratelimit_set_flags(&rs, RATELIMIT_MSG_ON_RELEASE);

    return 0;
}

static void __exit netlink_exit(void) {
    if (socket) {
        netlink_kernel_release(socket);
    }
}
