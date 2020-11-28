/**
 * @file fvaultd.c
 * @author 杨磊 (yangleisx@sjtu.edu.cn)
 * @brief 文件保险箱的服务器端程序，运行在后台。
 * 需要以root用户权限运行。连接数据库和内核模块。
 * @date 2020-11-13
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#define _GNU_SOURCE

#include <sqlite3.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ncheck.c"

// 创建数据库表
#define CREATE "CREATE TABLE IF NOT EXISTS fvault"\
			"("									\
				"inode INTEGER PRIMARY KEY,"	\
				"owner INTEGER"					\
			")"
// 通过用户uid查找文件
#define SELECT1 "SELECT inode FROM fvault WHERE owner = %u"
#define SELECT1_ROOT "SELECT inode, owner FROM fvault"
// 通过文件inode查找用户
#define SELECT2 "SELECT owner FROM fvault WHERE inode = %lu LIMIT 1"
#define SELECT_CHECK "SELECT 1 FROM fvault WHERE inode = %lu LIMIT 1"
// 插入数据
#define INSERT "INSERT INTO fvault VALUES (%lu, %u)"
// 删除数据
#define DELETE "DELETE FROM fvault WHERE inode = %lu"

// 服务器使用的socket路径
#define SOCK_PATH "/tmp/fvault.socket"
// 指定netlink协议，系统预定义了17种，这里定义新的类型
#define NETLINK_SAFE 30

char sql[64] = { 0 };
sqlite3 * db;
int req_len, rsp_len, rsp1_len, rc, server_sock, client_sock;

/**
 * @brief 向服务器发送的请求结构
 * op | 操作
 * 1  | 列出文件箱内的文件
 * 2  | 检查指定的文件是否在文件箱内
 * 4  | 将指定的文件加入文件箱
 * 8  | 将指定的文件从文件箱内删除
 * 
 */
struct req {
    unsigned char op;
    unsigned long ino;
} reqbuf;

/**
 * @brief 服务器回复的数据结构
 * stat | 含义
 * 4    | 文件主与当前用户不匹配
 * 2    | 文件已经位于文件箱(insert)或者不在文件箱内(delete)
 * 1    | 数据库操作错误
 * 0    | 一切正常
 * 仅当root用户发送check请求时，会返回文件所属用户的uid
 * 
 */
union rsp {
    unsigned int stat;
    uid_t uid;
} rspbuf;

/**
 * @brief 当发送list请求时回复的数据结构
 * 
 */
struct rsp1 {
    uid_t uid;
    char filename[4096];
} rsp1buf;

/**
 * @brief SQLite的回调函数
 * 用于根据用户ID查询数据库中的文件inode号。
 * 
 * @param NotUsed 保留位置用于用户指定的参数
 * @param argc 参数的数量（记录中字段的数量）
 * @param argv 每一个字段的值（这里为inode号）
 * @param azColName 每一个字段的名称（即表头）
 * @return int
 */
static int callback_get_filelist(void * NotUsed, int argc, char ** argv, char ** azColName) {
    // atol将char*类型转换为long类型
    unsigned long inode = (unsigned long)atol(argv[0]);

    get_filename_from_ino(inode, rsp1buf.filename);
    send(client_sock, & rsp1buf, rsp1_len, 0);

    return 0;
}

/**
 * @brief SQLite的回调函数
 * 用于查询数据库中所有的文件inode号和用户ID
 * 
 * @param NotUsed 保留位置用于用户指定的参数
 * @param argc 参数的数量（记录中字段的数量）
 * @param argv 每一个字段的值（这里为inode和owner）
 * @param azColName 每一个字段的名称
 * @return int 
 */
static int callback_get_filelist_root(void * NotUsed, int argc, char ** argv, char ** azColName) {
    unsigned long inode = (unsigned long)atol(argv[0]);

    rsp1buf.uid = (uid_t)atoi(argv[1]);
    get_filename_from_ino(inode, rsp1buf.filename);
    send(client_sock, & rsp1buf, rsp1_len, 0);

    return 0;
}

/**
 * @brief SQLite的回调函数
 * 用于根据文件inode查找用户uid或者检查inode是否在数据库中
 * 
 * @param result 用户指定的参数
 * @param argc 字段的数量
 * @param argv 每个字段的值（这里为inode或者常数1）
 * @param azColName 字段的名称
 * @return int
 */
static int callback_get_fileowner_or_check(void * result, int argc, char ** argv, char ** azColName) {
    // 根据inode查找用户
    // 将用户的id通过参数返回
    * (uid_t *)result = atoi(* argv);

    return 0;
}

/**
 * @brief 搜索文件箱内的文件
 * 
 * @param owner 用户的uid
 */
void select_get_filelist(uid_t owner) {
    if (owner) {
        // 非管理员用户的操作
        rsp1buf.uid = owner;
        snprintf(sql, 63, SELECT1, owner);
        // 对于db执行sql之后的每一条记录都会调用该回调函数
        rc = sqlite3_exec(db, sql, callback_get_filelist, 0, NULL);
    } else {
        // 管理员权限的操作
        strcpy(sql, SELECT1_ROOT);
        rc = sqlite3_exec(db, sql, callback_get_filelist_root, 0, NULL);
    }
}

/**
 * @brief 检查文件是否在文件箱内
 * 
 * @param inode 文件的inode号
 * @param owner 进行操作的用户
 */
void select_get_fileowner_or_check(unsigned long inode, uid_t owner) {
    uid_t result = 0;

    snprintf(sql, 63, SELECT2, inode);
    // 使用inode查找uid得到的结果存入result
    rc = sqlite3_exec(db, sql, callback_get_fileowner_or_check, & result, NULL);
    if (owner) {
        // 非管理员用户检查文件是否在保护
        // 4 - owner error
        rspbuf.stat = (owner == result) ? 0 : 4;
    } else {
        // 管理员用户查询文件的保护者
        rspbuf.uid = (unsigned long)result;
    }
    if (rc != SQLITE_OK) {
        // 数据库操作错误
        rspbuf.stat = 1;
    }
    send(client_sock, & rspbuf, rsp_len, 0);
}

/**
 * @brief 文件加入文件箱的操作
 * 
 * @param inode 文件的inode号
 * @param owner 进行操作的用户uid
 */
void insert(unsigned long inode, uid_t owner) {
    uid_t result = 0;

    // 根据文件inode检查用户uid
    snprintf(sql, 63, SELECT_CHECK, inode);
    rc = sqlite3_exec(db, sql, callback_get_fileowner_or_check, & result, NULL);
    if (result) {
        // 文件已经存在数据库中
        rspbuf.stat = 3;
    } else {
        if (! owner) {
            // 对于管理员用户并不执行加入操作
            rspbuf.stat = 5;
        } else {
            // 非管理员用户
            if ( owner == get_owner_from_ino(inode) ) {
                // check whether request from file owner
                snprintf(sql, 63, INSERT, inode, owner);
                rc = sqlite3_exec(db, sql, NULL, 0, NULL);
                rspbuf.stat = (rc == SQLITE_OK) ? 0 : 1;
            } else {
                // 不是文件的属主不能操作
                rspbuf.stat = 5;
            }
        }
    }
    send(client_sock, & rspbuf, rsp_len, 0);
}

/**
 * @brief 文件从文件箱中移出的操作
 * 
 * @param inode 文件的inode号
 * @param owner 进行操作的用户uid
 */
void delete(unsigned long inode, uid_t owner) {
    uid_t result = 0;

    // 查找文件主
    snprintf(sql, 63, SELECT2, inode);
    rc = sqlite3_exec(db, sql, callback_get_fileowner_or_check, & result, NULL);
    if (! result) {
        // 文件不在数据库中
        rspbuf.stat = 3;
    } else {
        if (! owner || owner == result) {	
			// 管理员用户或者文件主用户
            snprintf(sql, 63, DELETE, inode);
            rc = sqlite3_exec(db, sql, NULL, 0, NULL);
            rspbuf.stat = (rc == SQLITE_OK) ? 0 : 1;
        } else {
            rspbuf.stat = 5;
        }
    }
    send(client_sock, & rspbuf, rsp_len, 0);
}

/**
 * @brief 服务器端的主程序
 * 创建了一个子进程，父进程负责与内核模块的通信
 * 子进程负责与用户端进程之间的socket通信
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数首地址
 * @return int 
 */
int main(int argc, char ** argv) {
    // 用于socket连接的变量并初始化
    int sockaddr_len, ucred_len;
    struct sockaddr_un server_sockaddr, client_sockaddr;

    req_len = sizeof(struct req);
    rsp_len = sizeof(union rsp);
    rsp1_len = sizeof(struct rsp1);
    sockaddr_len = sizeof(struct sockaddr_un);
    memset(& server_sockaddr, 0, sockaddr_len);
    memset(& client_sockaddr, 0, sockaddr_len);
    // 用户凭证
    struct ucred cr;
    ucred_len = sizeof(struct ucred);

    // 连接数据库
    rc = sqlite3_open("fvault.db", & db);
    if (rc) {
        printf("%s\n", "SQLITE OPEN ERROR");
        sqlite3_close(db);
        exit(1);
    }

    // 创建数据表，存储文件inode和文件主uid
    rc = sqlite3_exec(db, CREATE, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        printf("%s\n", "CREATE TABLE ERROR");
        sqlite3_close(db);
        exit(1);
    }

    // 父进程使用netlink与内核模块通信
    if (fork()) {
        // netlink协议使用sockaddr_nl地址
        struct sockaddr_nl src_sockaddr, dest_sockaddr;
        struct nlmsghdr * nlh = NULL;
        struct msghdr msg;
        struct iovec iov;

        // 创建地址并初始化
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(unsigned long)));
        memset(& src_sockaddr, 0, sizeof(struct sockaddr_nl));
        memset(& dest_sockaddr, 0, sizeof(struct sockaddr_nl));
        memset(nlh, 0, NLMSG_SPACE(sizeof(unsigned long)));
        memset(& msg, 0, sizeof(struct msghdr));

        // 创建netlink的socket
        server_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SAFE);
        // 创建用户态地址，pid需要设置为进程的pid
        // 实际上是一个socket标识，不同线程可以设置为不同的值
        // groups为多播组，设置为0表示不加入多播
        src_sockaddr.nl_family = AF_NETLINK;
        src_sockaddr.nl_pid = getpid();
        src_sockaddr.nl_groups = 0;
        // 绑定socket和地址
        bind(server_sock, (struct sockaddr *)& src_sockaddr, sizeof(struct sockaddr_nl));
        // 设置核心态用户地址，核心态的pid必须设置为0
        dest_sockaddr.nl_family = AF_NETLINK;
        dest_sockaddr.nl_pid = 0;
        dest_sockaddr.nl_groups = 0;
        // 设置netlink socket的信息头部
        nlh -> nlmsg_len = NLMSG_SPACE(sizeof(unsigned long));
        nlh -> nlmsg_pid = getpid();
        nlh -> nlmsg_flags = 0;
        // 设置iov 可以把多个信息通过一次系统调用发送
        iov.iov_base = (void *)nlh;
        iov.iov_len = NLMSG_SPACE(sizeof(unsigned long));
        // 设置接收地址
        msg.msg_name = (void *)& dest_sockaddr;
        msg.msg_namelen = sizeof(struct sockaddr_nl);
        msg.msg_iov = & iov;
        msg.msg_iovlen = 1;

        // 填充并发送初始化就绪数据
        * (unsigned long *)NLMSG_DATA(nlh) = (unsigned long)0xffffffff << 32;
        sendmsg(server_sock, & msg, 0);
        while (1) {
            // 接收内核态的信息
            recvmsg(server_sock, & msg, 0);
            // 查询指定文件的属主
            snprintf(sql, 63, SELECT2, * (unsigned long *)NLMSG_DATA(nlh));
            * (unsigned long *)NLMSG_DATA(nlh) = 0;
            sqlite3_exec(db, sql, callback_get_fileowner_or_check, (uid_t *)NLMSG_DATA(nlh), NULL);
            // 将查询结果发送到内核
            sendmsg(server_sock, & msg, 0);
        }

        // 关闭socket和数据库，释放内存
        close(server_sock);
        free(nlh);
        sqlite3_close(db);
    }
    // 子进程使用socket与客户端之间通信
    else {
        ext2fs_init();

        // 创建服务器socket
        server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_sock == -1) {
            printf("%s\n", "SOCKET ERROR");
            exit(1);
        }

        // 连接服务器socket文件
        server_sockaddr.sun_family = AF_UNIX;
        strcpy(server_sockaddr.sun_path, SOCK_PATH);
        unlink(SOCK_PATH);
        rc = bind(server_sock, (struct sockaddr *)& server_sockaddr, sockaddr_len);
        if (rc == -1) {
            printf("%s\n", "BIND ERROR");
            close(server_sock);
            exit(1);
        }

        // 等待连接
        chmod(SOCK_PATH, 0666);
        rc = listen(server_sock, 16);
        if (rc == -1) {
            printf("%s\n", "LISTEN ERROR");
            close(server_sock);
            exit(1);
        }

        while (1) {
            // 接受客户端socket连接
            client_sock = accept(server_sock, (struct sockaddr *)& client_sockaddr, & sockaddr_len);
            if (client_sock == -1) {
                close(client_sock);
                continue;
            }
            // 接受客户端发送的请求数据
            rc = recv(client_sock, & reqbuf, req_len, 0);
            if (rc == -1) {
                close(client_sock);
                continue;
            }
            // SOL_SOCKET表示socket级别（不变）
            // SO_PEERCRED表示获取对方的身份凭证
            if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, & cr, & ucred_len) == -1) {
                close(client_sock);
                continue;
            }
            // 根据请求的类型进行处理
            switch (reqbuf.op) {
            case 1:
                // 发送列出的文件
                select_get_filelist(cr.uid);
                break;
            case 2:
                // 检查文件是否在文件箱内
                select_get_fileowner_or_check(reqbuf.ino, cr.uid);
                break;
            case 4:
                // 将文件加入文件箱内
                insert(reqbuf.ino, cr.uid);
                break;
            case 8:
                // 将文件从文件箱移除
                delete(reqbuf.ino, cr.uid);
                break;
            }
            // 传输结束以后关闭连接
            close(client_sock);
        }
        // 关闭socket和数据库连接
        close(server_sock);
        close(client_sock);
        sqlite3_close(db);
    }

    return 0;
}
