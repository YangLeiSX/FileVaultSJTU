/*
** This is a modified version of ncheck.c from e2fsprogs/debugfs.
** Special thanks to the original author, Theodore Ts'o.
*/

#include <ext2fs/ext2fs.h>
#include <sys/stat.h>

static ext2_filsys current_fs;

struct inode_walk_struct {
    ext2_ino_t		dir;
    ext2_ino_t		inode;
    int			names_left;
    int			position;
    char			*parent;
    char			*filename;
    unsigned int		get_pathname_failed:1;
};

static int ncheck_proc(struct ext2_dir_entry *dirent,
                       int	offset EXT2FS_ATTR((unused)),
                       int	blocksize EXT2FS_ATTR((unused)),
                       char	*buf EXT2FS_ATTR((unused)),
                       void	*private) {
    struct inode_walk_struct *iw = (struct inode_walk_struct *) private;
    errcode_t retval;

    iw->position++;
    if (iw->position <= 2)
        return 0;
    if (iw->inode == dirent->inode) {
        if (!iw->parent && !iw->get_pathname_failed) {
            retval = ext2fs_get_pathname(current_fs,
                                         iw->dir,
                                         0, &iw->parent);
            if (retval) {
                iw->get_pathname_failed = 1;
            }
        }
        if (iw->parent)
            snprintf(iw->filename, 4095,
                     "%s/%.*s", iw->parent,
                     ext2fs_dirent_name_len(dirent),
                     dirent->name);
        else
            snprintf(iw->filename, 4095,
                     "<%u>/%.*s", iw->dir,
                     ext2fs_dirent_name_len(dirent),
                     dirent->name);
        iw->names_left = 0;
        return DIRENT_ABORT;
    }

    return 0;
}

void get_filename_from_ino(unsigned long i_no, char *filename) {
    struct inode_walk_struct iw;
    ext2_inode_scan scan = 0;
    ext2_ino_t ino;
    struct ext2_inode inode;
    errcode_t retval;

    iw.names_left = 1;
    iw.inode = i_no;
    iw.filename = filename;
    ext2fs_read_inode(current_fs, iw.inode, &inode);
    ext2fs_open_inode_scan(current_fs, 0, &scan);
    do {
        retval = ext2fs_get_next_inode(scan, &ino, &inode);
    } while (retval == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE);

    while (ino) {
        if (!inode.i_links_count)
            goto next;
        if (inode.i_dtime)
            goto next;
        if (!LINUX_S_ISDIR(inode.i_mode))
            goto next;
        iw.position = 0;
        iw.parent = 0;
        iw.dir = ino;
        iw.get_pathname_failed = 0;
        retval = ext2fs_dir_iterate(current_fs, ino, 0, 0, ncheck_proc, &iw);
        ext2fs_free_mem(&iw.parent);
        if (retval) {
            goto next;
        }
        if (iw.names_left == 0)
            break;

next:
        do {
            retval = ext2fs_get_next_inode(scan, &ino, &inode);
        } while (retval == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE);
    }
}

uid_t get_owner_from_ino(unsigned long i_no) {
    struct ext2_inode inode;

    ext2fs_read_inode(current_fs, i_no, &inode);
    if (LINUX_S_ISLNK(inode.i_mode)) {
        char filename[4096];
        struct stat statbuf;

        get_filename_from_ino(i_no, filename);
        stat(filename, &statbuf);
        return statbuf.st_uid;
    } else {
        return (inode.osd2.linux2.l_i_uid_high << 16) + inode.i_uid;
    }
}

void ext2fs_init(void) {
    ext2fs_open("/dev/sda1", EXT2_FLAG_64BITS | EXT2_FLAG_SOFTSUPP_FEATURES, 0, 0, unix_io_manager, & current_fs);
}
