/**
 * @file netlink.c
 * @author 杨磊 (yangleisx@sjtu.edu.cn)
 * @brief 实现内核态netlink通信
 * @date 2020-11-13
 * 
 * @copyright Copyright (c) 2020
 * 
 */
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

/**
 * @brief 消息队列
 * 使用信号量保护的数据队列，保存用户态返回的数据
 * 
 */
static struct queue {
    uid_t data[65536];
    struct semaphore sem[65536];
} rspbuf;

// 配置定时器频率
DEFINE_RATELIMIT_STATE(rs, 3 * HZ, 1);

/**
 * @brief 使用netlink与用户态通信查询文件主
 * 使用自增的原子序数作为netlink信息的序列号
 * 创建长度65535的数据队列保存用户态返回的数据
 * 
 * @param inode 
 * @return uid_t 
 */
static uid_t get_owner(unsigned long inode) {
    // sk_buff是内核态存储网络数据的重要结构
    struct sk_buff* skb;
    struct nlmsghdr* nlh;
    unsigned short seq;

    // 用户态的服务器程序尚未开启
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

    // 等待用户态返回的数据存入指定的位置
    // 检查数据队列的信号量
    // 最长等待3s，如果服务器没有发送信息则自动终止
    if (down_timeout(&rspbuf.sem[seq], 3 * HZ)) {
        if (__ratelimit(&rs)) {
            pid = 0;
            printk(KERN_NOTICE "[fvault] fvault terminated!\n");
        }
        return 0;
    }

    return rspbuf.data[seq];
}

/**
 * @brief 内核态netlink的接收回调函数
 * 结束到数据时调用该函数
 * 
 * @param skb 接收到的网络报文
 */
static void nl_receive_callback(struct sk_buff* skb) {
    // 获得网络报文中的netlink数据
    struct nlmsghdr* nlh = (struct nlmsghdr*)skb->data;

    // 检查收到的数据是否为初始化信号
    if (*(unsigned long*)NLMSG_DATA(nlh) >> 32 != 0xffffffff) {
        // 将用户态回复的数据按照序列号存入对应的位置
        rspbuf.data[nlh->nlmsg_seq] = *(uid_t*)NLMSG_DATA(nlh);
        up(&rspbuf.sem[nlh->nlmsg_seq]);
    } else {
        // 接收到了初始化信号哦
        // 提取服务器进程的pid保存在全局变量中
        if (NETLINK_CREDS(skb)->pid == nlh->nlmsg_pid && !NETLINK_CREDS(skb)->uid.val) {
            printk(KERN_NOTICE "[fvault] fvault initiated!\n");
            pid = nlh->nlmsg_pid;
        }
    }
}

/**
 * @brief 内核模块初始化函数
 * 创建netlink的socket并初始化
 * 
 * @return int 
 */
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
    // 初始化等待时间标志位
    ratelimit_set_flags(&rs, RATELIMIT_MSG_ON_RELEASE);

    return 0;
}

/**
 * @brief 内核模块的出口函数
 * 
 */
static void __exit netlink_exit(void) {
    // 释放socket
    if (socket) {
        netlink_kernel_release(socket);
    }
}
