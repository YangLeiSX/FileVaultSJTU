/**
 * @file fvault.c
 * @author 杨磊 (yangleisx@sjtu,edu.cn)
 * @brief 文件保险箱的CLI客户端
 * @date 2020-11-13
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include <sys/un.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>

// Unix Domain Socket通信使用的socket文件路径
#define SERVER_PATH "/tmp/fvault.socket"
#define CLIENT_PATH "/tmp/fvault.%u.socket"

/**
 * @brief 向服务器发送的请求结构
 * op | 操作
 * 1  | 列出文件箱内的文件
 * 2  | 检查指定的文件是否在文件箱内
 * 4  | 将指定的文件加入文件箱
 * 8  | 将指定的文件从文件箱内删除
 */
struct req {
    unsigned char op;
    unsigned long ino;
};

/**
 * @brief 服务器回复的数据结构
 * stat | 含义
 * 4    | 文件主与当前用户不匹配
 * 2    | 文件已经位于文件箱(insert)或者不在文件箱内(delete)
 * 1    | 数据库操作错误
 * 0    | 一切正常
 * 仅当root用户发送check请求时，会返回文件所属用户的uid
 */
union rsp {
    unsigned char stat;
    uid_t uid;
};

/**
 * @brief 当发送list请求时回复的数据结构
 * 
 */
struct rsp1 {
    uid_t uid;
    char filename[4096];
};

// 加入或者移出文件时的文件路径和缓存路径
char src_file[4092];
char buf_file[4096];

/**
 * @brief 复制文件内容
 * 在加入或者删除文件的时候读写复制文件内容
 * 
 * @param src_file 原文件的文件名
 * @param dst_file 目标文件的文件名
 */
void rw_file(char* src_file, char* dst_file) {
    int fin, fout;
    fin = open(src_file, O_RDONLY, 0644);
    fout = open(dst_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int n;
    char buf[1024];
    while((n = read(fin, buf, 1024))){
       write(fout, buf, n);
    }
    close(fin);
    close(fout);
}

/**
 * @brief 客户端的主要处理函数
 * 与服务器建立连接，发送请求并获得服务器的返回数据
 * 
 * @param op 操作类型
 * @param ino 文件的inode节点号
 */
void handle(unsigned char op, unsigned long ino) {
    int client_sock, rc, sockaddr_len;
    // 这里使用的是sockaddr_un表示Unix域套接字地址
    // 通常在internet传输中使用sockaddr_in表示互联网域地址
    struct sockaddr_un server_sockaddr, client_sockaddr;
    struct req reqbuf = {op, ino};
    union rsp rspbuf;
    struct rsp1 rsp1buf;
    // 查看用户名和密码的结构
    struct passwd * pwd;

    // 清空socket地址
    sockaddr_len = sizeof(struct sockaddr_un);
    memset(& server_sockaddr, 0, sockaddr_len);
    memset(& client_sockaddr, 0, sockaddr_len);

    // 创建Unix域的socket
    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sock == -1) {
        printf("%s\n", "SOCKET ERROR");
        exit(1);
    }

    // 创建客户端socket文件并绑定到套接字
    client_sockaddr.sun_family = AF_UNIX;
    snprintf(client_sockaddr.sun_path, 107, CLIENT_PATH, getuid());
    unlink(client_sockaddr.sun_path); // 防止上次使用忘记删除
    rc = bind(client_sock, (struct sockaddr *)& client_sockaddr, sockaddr_len);
    if (rc == -1) {
        printf("%s\n", "BIND ERROR");
        close(client_sock);
        exit(1);
    }

    // 连接到服务器端socket文件
    // 与Internet不同，直接使用connect连接到一个已经打开的socket文件
    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, SERVER_PATH);
    rc = connect(client_sock, (struct sockaddr *)& server_sockaddr, sockaddr_len);
    if (rc == -1) {
        printf("%s\n", "CONNECT ERROR");
        close(client_sock);
        exit(1);
    }

    // 发送请求
    rc = send(client_sock, & reqbuf, sizeof(struct req), 0);
    if (rc == -1) {
        printf("%s\n", "SEND ERROR");
        close(client_sock);
        exit(1);
    }

    // 接受数据并处理结果
    if (op == 1) {
        rc = recv(client_sock, & rsp1buf, sizeof(struct rsp1), 0);
    } else {
        rc = recv(client_sock, & rspbuf, sizeof(union rsp), 0);
    }
    if (rc == -1) {
        printf("%s\n", "RECV ERROR");
        close(client_sock);
        exit(1);
    }


    // 处理结果
    switch (op) {
    case 1:
        // 对于list操作
        printf("%s\n", "FILE LIST:");
        if (getuid()) {
            // 非管理员用户可以查看自己所属的文件
            // 在服务器端使用getsockopt函数获得用户ID信息
            printf("%s\n", "filename");
            while (rc > 0) {
                printf("%s\n",rsp1buf.filename);
                rc = recv(client_sock, & rsp1buf, sizeof(struct rsp1), 0);
            }
        } else {
            // 管理员用户可以查看所有的文件信息
            printf("%s\t%s\n", "owner", "filename");
            while (rc > 0) {
                pwd = getpwuid(rsp1buf.uid);
                printf("%s\t%s\n", pwd -> pw_name, rsp1buf.filename);
                rc = recv(client_sock, & rsp1buf, sizeof(struct rsp1), 0);
            }
        }
        break;
    case 2:
        // 对于check操作
        if (getuid()) {
            // 非管理员用户
            if (rspbuf.stat & 1) {
                printf("%s\n", "CHECK FAILED!");
            } else {
                if (rspbuf.stat & 4) printf("%s\n", "FILE NOT UNDER YOUR PROTECTION.");
                else printf("%s\n", "FILE UNDER YOUR PROTECTION.");
            }
        } else {
            // 管理员用户可以检查文件的属主
            if (rspbuf.uid) {
                pwd = getpwuid(rspbuf.uid);
                printf("owner: %u\tusername: %s\n", rspbuf.uid, pwd->pw_name);
            } else printf("%s\n", "CHECK OWNER FAILED!");
        }
        break;
    case 4:
        // 对于插入操作
        if (rspbuf.stat & 1) {
            printf("%s\t", "INSERT FAILED:");
            if (rspbuf.stat & 2) {
                printf("%s\n", "FILE ALREADY PROTECTED!");
            }
            if (rspbuf.stat & 4) {
                printf("%s\n", "FILE NOT OWNED BY YOU!");
            }
        } else {
            printf("%s\n", "INSERT SUCCEEDED.");
            // 将原文加密写入
            rw_file(buf_file, src_file);
        }
        // 删除缓存文件
        unlink(buf_file);
        break;
    case 8:
        // 对于删除操作
        if (rspbuf.stat & 1) {
            printf("%s\t", "DELETE FAILED:");
            if (rspbuf.stat & 2) {
                printf("%s\n", "FILE NOT PROTECTED YET!");
            }
            if (rspbuf.stat & 4) {
                printf("%s\n", "FILE NOT OWNED BY YOU!");
            }
        } else {
            printf("%s\n", "DELETE SUCCEEDED.");
            // 将密文解密
            rw_file(buf_file, src_file);
        }
        // 删除缓存文件
        unlink(buf_file);
        break;
    }

    // 关闭socket 删除文件
    close(client_sock);
    // 使用结束后需要删除
    unlink(client_sockaddr.sun_path);
}

/**
 * @brief 显示CLI客户端的命令行参数和用法
 * 
 */
void usage(void) {
    printf("%s\n", "Usage: fvault [OPTION]... [FILE]...\n\n"
           "  -l (list)	list all files under protection\n"
           "  -c (check)	check whether file is under protection;\n"
           "  		for root check owner of given file\n"
           "  -i (insert)	insert given file into protection area\n"
           "  -d (delete)	delete given file from protection area\n");
}

/**
 * @brief 主函数，程序入口
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数的首地址数组
 * @return int 
 */
int main(int argc, char ** argv) {
    int ch;
    unsigned char option = 0;
    unsigned long inode = 0;
    struct stat file_stat;
    // 检查参数，如果一个连字符后面多个选项，只识别最后一个
    // 例如：fvault -cl等价于fvault -l
    while ((ch = getopt(argc, argv, "lcid")) != -1) {
        switch (ch) {
        case 'l':
            option = 1;
            break;
        case 'c':
            option = 2;
            break;
        case 'i':
            option = 4;
            break;
        case 'd':
            option = 8;
            break;
        default:
            usage();
            return -1;
        }
    }
    // 如果是cid但是没有文件名，就会触发(argc < 3 && option > 1)
    // 例如：fvault -i
    // 如果是输入了lcid中一个以上，就会触发optind != 2
    // 例如：fvault -c -l
    if (optind != 2 || (argc < 3 && option > 1)) {
        usage();
        return -1;
    }
    // 处理list的情况
    if (option == 1) {
        handle(option, 0);
        return 0;
    }
    // 对于cid的情况依次处理每个文件
    // 例如：fvault -i file1.txt file2.txt ...
    while (optind < argc) {
        // 获得所处理的文件名，生成缓冲文件名
        memset(src_file, 0, 4096);
        memset(buf_file, 0, 4096);
        memcpy(src_file, argv[optind], strlen(argv[optind]));
        snprintf(buf_file, 4096, "%s.buf", src_file);
        // 检查文件状态并处理
        if (! stat(argv[optind++], &file_stat)) {
            if (getuid() == file_stat.st_uid || option == 2) {
                // 将原文件复制保存在缓冲文件中
                if (option == 4 || option == 8) {
                    rw_file(src_file, buf_file);
                }
                // 获得文件的inode节点号去处理
                inode = file_stat.st_ino;
                handle(option, inode);
            } else {
                printf("Operation not Permitted\n");
            }
        } else {
            printf("%s: No such file or directory\n", argv[optind - 1]);
        }
    }
    return 0;
}
