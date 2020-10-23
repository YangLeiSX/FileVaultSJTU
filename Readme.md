# FileVaultSJTU

上海交通大学

系统软件课程设计课程，Linux内核模块编程

实现基于系统调用重载的加密型文件保险箱

## 系统组成

内核态编写了系统调用重载的内核模块，重载文件相关的系统调用。

用户态编写了客户端和服务器，客户端使用CLI进行操作，服务器对SQLITE数据库进行操作。

客户端和服务器使用UNIX域socket通信。服务器与内核模块使用netlink通信。

## 现存问题

1. (fixed by modity kernel/crypto.c)文件加解密的操作仍需完善（使用kmalloc结合copy_from_user/copy_to_user）
2. 文件加入和移除保险箱时的加解密操作
3. 删除文件后数据库内保存的文件名信息出错
4. (tested but not for sure)可执行文件加入保险箱后是否可以正常运行
5. filename of inode have been changed by "gedit", seems like problem #3 above
