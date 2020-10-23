#include "crypto.c"
#include "netlink.c"
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

MODULE_LICENSE("GPL");

// 定义了一种函数指针的别名为sys_call_ptr_t
typedef void (*sys_call_ptr_t)(void);
// 定义了一种函数指针的别名为old_syscal_t
// 参数为struct pt_regs*
typedef asmlinkage ssize_t (*old_syscall_t)(struct pt_regs* regs);
// pt_regs保存了用户态CPU寄存器的核心栈内容

old_syscall_t old_read = NULL;
old_syscall_t old_write = NULL;
old_syscall_t old_execve = NULL;
old_syscall_t old_rename = NULL;
old_syscall_t old_unlink = NULL;
old_syscall_t old_unlinkat = NULL;
old_syscall_t old_getdents64 = NULL;
old_syscall_t old_openat = NULL;

sys_call_ptr_t* sys_call_table = NULL;
pte_t* pte = NULL;
unsigned int level = 0;

/*
** The following two functions get inode number from fd or from filename.
** Note we intensionally exclude character device file and block device file from
** further privilege check, so the safe won't degrade system performance.
*/
static unsigned long get_ino_from_fd(unsigned int fd) {
    struct fd f = fdget(fd);
    umode_t mode = 0;
    unsigned long ino = 0;

    if (!IS_ERR(f.file)) {
        mode = f.file->f_inode->i_mode;
        if (!S_ISCHR(mode) && !S_ISBLK(mode)) {
            ino = f.file->f_inode->i_ino;
        }
        fdput(f);
    }

    return ino;
}

static unsigned long get_ino_from_name(int dfd, const char* filename) {
    struct kstat stat;
    umode_t mode = 0;
    unsigned long ino = 0;
    int error = vfs_statx(dfd, filename, AT_NO_AUTOMOUNT, &stat, STATX_BASIC_STATS);

    if (!error) {
        mode = stat.mode;
        if (!S_ISCHR(mode) && !S_ISBLK(mode)) {
            ino = stat.ino;
        }
    }

    return ino;
}

/*
** Check privilege for hooked read, write, execve, getdents64 syscall.
** Privilege 2 indicates file is not in safe, or the request is from root,
** in which case original syscall will be executed;
** Privilege 1 indicates file is in safe, and the request is from owner,
** in which case original syscall along with patch (excrypt, decrypt...) will be executed;
** Privilege 0 indicates file is in safe, and the request is not from owner,
** in which case syscall will be refused to execute.
** Note the first 10 reserved inodes are excluded from privilege check.
*/
static unsigned char check_privilege(unsigned long ino, uid_t uid) {
    uid_t owner = 0;
    unsigned char privilege = 2;

    if (ino > 10 && uid) {
        owner = get_owner(ino);
    }
    if (owner) {
        privilege = (owner == uid) ? 1 : 0;
    }

    return privilege;
}

/*
** Check protection for hooked unlink, unlinkat syscall.
** Privilege 1 indicates file is not in safe, in which case original syscall will be executed;
** Privilege 0 indicates file is in safe, in which case syscall will be refused to execute.
** Note the first 10 reserved inodes are excluded from protection check.
*/
static unsigned char check_protection(unsigned long ino) {
    uid_t owner = 0;

    if (ino > 10) {
        owner = get_owner(ino);
    }

    return (owner == 0);
}

// 获得文件上一次读写之后的位置
static loff_t get_pos_from_fd(unsigned int fd, unsigned char op) {
    loff_t pos = 0;
    struct fd f = fdget(fd);

    if (f.file) {
        if (op && (f.file->f_flags & O_APPEND)) {
            struct kstat stat;
            vfs_fstat(fd, &stat);
            pos = stat.size;
        } else {
            pos = f.file->f_pos;
        }
        fdput(f);
    }

    return pos;
}

/*
** The following functions are hooked syscalls, which check file privilege or
** protection for specific user, and execute corresponding operation.
**
** Note Linux follows System V AMD64 ABI calling convention, so:
** rdi				|rsi				|rdx				|r10
** first parameter	|second parameter	|third parameter	|fourth parameter
*/

/*
** ssize_t read(unsigned int fd, char * buf, size_t count);
*/
asmlinkage ssize_t hooked_read(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
    loff_t pos = 0;
    
    // 获得读取文件的信息，文件名保存在rdi中
    ino = get_ino_from_fd(regs->di);
    uid = current_uid().val;
    // 检查访问权限
    switch (check_privilege(ino, uid)) {
    case 2:
        ret = old_read(regs);
        break;
    case 1:
        // 用户访问，解密
        pos = get_pos_from_fd(regs->di, 0);
        ret = old_read(regs);
        // 文件内容读取后保存在rsi中
        // pos为读取文件的偏移量
        transform((char*)regs->si, ino, pos, ret);
        break;
    case 0:
        ;
    }

    return ret;
}

/*
** ssize_t write(unsigned int fd, const char * buf, size_t count);
*/
asmlinkage ssize_t hooked_write(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;
    loff_t pos = 0;

    // 获得写文件的信息，文件名位于rdi
    ino = get_ino_from_fd(regs->di);
    uid = current_uid().val;
    // 检查权限
    switch (check_privilege(ino, uid)) {
    case 2:
        ret = old_write(regs);
        break;
    case 1:
        // 找到上次读写的位置
        pos = get_pos_from_fd(regs->di, 1);
        // 读取rdi加密后写入ino+pos，写入的数量存在rdx中
        transform((char*)regs->si, ino, pos, regs->dx);
        ret = old_write(regs);
        break;
    case 0:
        ;
    }

    return ret;
}

/*
** ssize_t execve(const char * filename, const char * const argv[], const char * const envp[]);
*/
// TODO: 这一部分需要完善
asmlinkage ssize_t hooked_execve(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;

    // 获得参数的内容
    // 文件名位于rdi
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->di);
    uid = current_uid().val;
    switch (check_privilege(ino, uid)) {
    case 2:
        ret = old_execve(regs);
        break;
    case 1:
        ret = old_execve(regs);
        break;
    case 0:
        ;
    }

    return ret;
}

/*
** ssize_t rename(const char * oldname, const char * newname);
*/
asmlinkage ssize_t hooked_rename(struct pt_regs* regs) {
    unsigned long ino;
    ssize_t ret = -1;

    // Magic! Do not Modify!
    // Test 'mv' Command:
    //   使用rdi(oldname)，不管是本用户还是其他用户都是not permitted
    //   使用rsi(newname)，本用户可以正常修改，其他用户无法修改
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->si);
    if (check_protection(ino)) {
        ret = old_rename(regs);
    }

    return ret;
}

/*
** ssize_t unlink(const char * pathname);
*/
asmlinkage ssize_t hooked_unlink(struct pt_regs* regs) {
    unsigned long ino;
    ssize_t ret = -1;

    // 从rdi中读取文件名获得inode
    ino = get_ino_from_name(AT_FDCWD, (char*)regs->di);
    if (check_protection(ino)) {
        ret = old_unlink(regs);
    }

    return ret;
}

/*
** ssize_t unlinkat(int dfd, const char * pathname, int flag);
*/
asmlinkage ssize_t hooked_unlinkat(struct pt_regs* regs) {
    unsigned long ino;
    ssize_t ret = -1;
    
    // 从rsi中读取文件名以获得inode号
    ino = get_ino_from_name(regs->di, (char*)regs->si);
    if (check_protection(ino)) {
        ret = old_unlinkat(regs);
    }

    return ret;
}

/*
** ssize_t getdents64(unsigned int fd, struct linux_dirent64 * dirent, unsigned int count);
*/
asmlinkage ssize_t hooked_getdents64(struct pt_regs* regs) {
    uid_t uid;
    ssize_t ret = -1;
    int copylen = 0;
    struct linux_dirent64 *filtered_dirent;
    struct linux_dirent64 *orig_dirent;
    struct linux_dirent64 *td1;
    struct linux_dirent64 *td2;

    uid = current_uid().val;
    ret = old_getdents64(regs);

    // empty Directory 
    if (ret == 0) return ret;

    // allocate memory space
    filtered_dirent = (struct linux_dirent64*)kmalloc(ret, GFP_KERNEL);
    td1 = filtered_dirent;
    orig_dirent = (struct linux_dirent64*)kmalloc(ret, GFP_KERNEL);
    td2 = orig_dirent;
    // get directory entries
    copy_from_user(orig_dirent, (void *)regs->si, ret);

    // iterate directory entries
    while (ret > 0) {
        ret -= td2->d_reclen;
        if (check_privilege(td2->d_ino, uid)) {
            // select an entry
            memmove(td1, (char *)td2, td2->d_reclen);
            td1 = (struct linux_dirent64*)((char *)td1 + td2->d_reclen);
            copylen += td2->d_reclen;
        }
        td2 = (struct linux_dirent64*)((char *)td2 + td2->d_reclen);
    }

    copy_to_user((void *)regs->si, filtered_dirent, copylen);
    // free kernel memory
    kfree(orig_dirent);
    kfree(filtered_dirent);

    return copylen;
}

/*
** ssize_t openat(int dfd, const char * filename, int flags, int mode);
*/
asmlinkage ssize_t hooked_openat(struct pt_regs* regs) {
    unsigned long ino;
    uid_t uid;
    ssize_t ret = -1;

    // 获得inode节点
    ino = get_ino_from_name(regs->di, (char*)regs->si);
    uid = current_uid().val;
    if (check_privilege(ino, uid)) {
        ret = old_openat(regs);
    }

    return ret;
}

/*
** Get sys_call_table address.
*/
static sys_call_ptr_t* get_sys_call_table(void) {
    sys_call_ptr_t* _sys_call_table = NULL;

    _sys_call_table = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");

    return _sys_call_table;
}

/*
** Initialize kernel netlink module and hook syscalls.
*/
static int __init hook_init(void) {
    // netlink初始化
    netlink_init();

    // 记录原本的系统调用
    sys_call_table = get_sys_call_table();
    old_read = (old_syscall_t)sys_call_table[__NR_read];
    old_write = (old_syscall_t)sys_call_table[__NR_write];
    old_execve = (old_syscall_t)sys_call_table[__NR_execve];
    old_rename = (old_syscall_t)sys_call_table[__NR_rename];
    old_unlink = (old_syscall_t)sys_call_table[__NR_unlink];
    old_unlinkat = (old_syscall_t)sys_call_table[__NR_unlinkat];
    old_getdents64 = (old_syscall_t)sys_call_table[__NR_getdents64];
    old_openat = (old_syscall_t)sys_call_table[__NR_openat];
    // 修改内存页权限
    pte = lookup_address((unsigned long)sys_call_table, &level);
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写入新的系统调用
    sys_call_table[__NR_read] = (sys_call_ptr_t)hooked_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)hooked_write;
    sys_call_table[__NR_execve] = (sys_call_ptr_t)hooked_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)hooked_rename;
    sys_call_table[__NR_unlink] = (sys_call_ptr_t)hooked_unlink;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)hooked_unlinkat;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)hooked_getdents64;
    sys_call_table[__NR_openat] = (sys_call_ptr_t)hooked_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    return 0;
}

/*
** Unhook syscalls and release kernel netlink module.
*/
static void __exit hook_exit(void) {
    // 修改内存页权限
    set_pte_atomic(pte, pte_mkwrite(*pte));
    // 写回原本的系统调用
    sys_call_table[__NR_read] = (sys_call_ptr_t)old_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)old_write;
    sys_call_table[__NR_execve] = (sys_call_ptr_t)old_execve;
    sys_call_table[__NR_rename] = (sys_call_ptr_t)old_rename;
    sys_call_table[__NR_unlink] = (sys_call_ptr_t)old_unlink;
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)old_unlinkat;
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)old_getdents64;
    sys_call_table[__NR_openat] = (sys_call_ptr_t)old_openat;
    // 恢复内存页权限
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    // netlink资源回收
    netlink_exit();
}

// 内核模块入/出口注册
module_init(hook_init);
module_exit(hook_exit);
