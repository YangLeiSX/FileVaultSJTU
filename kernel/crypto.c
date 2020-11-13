/**
 * @file crypto.c
 * @author 杨磊 (yangleisx@sjtu.edu.cn)
 * @brief 实现内核态加密和散列操作
 * @date 2020-11-13
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/cred.h>
#include <linux/scatterlist.h>

/**
 * @brief 通过用户的uid创建密钥
 *
 * @param key 长度为256bit的密钥首地址
 */
static void generate_key(unsigned char* key) {
    struct shash_desc sdesc;
    uid_t uid = current_uid().val;
    short i;

    // 申请运算上下文，指定算法为crc32-pclmul
    sdesc.tfm = crypto_alloc_shash("crc32-pclmul", 0, 0);
    // 这里选择的hash算法每次生成32bit(4Byte)长度的输出
    // 满足32Byte(256bit）长度的密钥需要迭代生成
    // 每次使用之前生成的部分计算哈希，将结果与之前的结果拼接起来
    crypto_shash_digest(&sdesc, (char*)&uid, sizeof(uid_t), key + 28);
    for (i = 28; i > 0; i -= 4) {
        crypto_shash_digest(&sdesc, key + i, 32 - i, key + i - 4);
    }
    // 释放空间
    crypto_free_shash(sdesc.tfm);
}

/**
 * @brief 通过访问文件的Inode值和偏移量创建初始化向量iv
 *
 * @param iv 长度为128bit的初始化向量iv首地址
 * @param inode 访问文件的inode编号
 * @param offset 访问文件的偏移量
 * loff_t类型定义为__kernel_loff_t
 * 在5.18.0中定义为long long，长度64bit
 */
static void generate_iv(char* iv, unsigned long inode, loff_t offset) {
    struct shash_desc sdesc;
    short i;
    // 申请运算上下文，指定算法为crc32-pclmul
    sdesc.tfm = crypto_alloc_shash("crc32-pclmul", 0, 0);
    // 使用inode值，迭代两次生成初始化向量iv的前8Byte
    crypto_shash_digest(&sdesc, (char*)&inode, sizeof(unsigned long), iv + 4);
    crypto_shash_digest(&sdesc, iv + 4, 4, iv);
    crypto_free_shash(sdesc.tfm);
    // 使用偏移量作为初始化向量的后8byte
    for (i = 0; i < sizeof(loff_t); ++i) {
        iv[15 - i] = ((char*)&offset)[i];
    }
}

/**
 * @brief 使用AES算法的CTR模式对于文件读写过程中的缓冲区加解密。
 * 具体的加解密过程为使用密钥对自增算子加密，之后与明文异或得到密文。
 * 密钥使用用户的uid生成，初始化向量iv使用文件的inode和读写位置生成
 *
 * @param ubuf 读写缓冲区的首地址，位于用户空间
 * @param inode 文件的inode节点
 * @param offset 读写文件的位置/偏移量
 * @param count 实际发生读写的字节数
 */
static void transform(char* ubuf, unsigned long inode, loff_t offset, size_t count) {
    struct crypto_skcipher* skcipher = NULL;
    struct skcipher_request* req = NULL;
    struct scatterlist sg;
    // 密钥和初始化向量的空间
    unsigned char key[32] = { 0 };
    char ivdata[16] = { 0 };
    // 处理时以16Byte(128bit)为单位
    // 将文件分为16Byte的分段时，偏移量低四位表示位于上一分段的字节数
    // 因此需要额外处理，将上一分段读取出来
    short pre_len = offset & 0xf;
    char prefix[15] = { 0 };
    // 创建内核态的缓冲区并复制数据
    char* buf;
    buf = (char*)kmalloc(count + pre_len, GFP_KERNEL);
    copy_from_user(buf + pre_len, (void *)ubuf, count);

    // 为算法申请内核中运算的上下文
    // 在crypto_alg_list链表中查询，找到AES的CTR模式并注册
    // 在内核中为该算法的各个函数指针初始化
    skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
    // 在该上下文空间中申请数据处理请求
    // 实际上完成了后台的内存申请和绑定
    req = skcipher_request_alloc(skcipher, GFP_KERNEL);

    // 创建256bit的密钥，并写入本次运算的上下文内存中
    generate_key(key);
    crypto_skcipher_setkey(skcipher, key, 32);

    // 创建初始化向量iv
    generate_iv(ivdata, inode, offset >> 4);
    // 在内存空间中开辟并维护一段内存
    // scatterlist用于维护大段的被多个组件访问的内存（例如，CPU和DMA）
    // 根据位于上一分段的字节数扩展需要的内存
    sg_init_one(&sg, buf, count + pre_len);

    // 将待加密数据放入本次运算的请求空间
    // 第二/三参数分别表示source和destination
    // 第四/五参数为待加密数据的长度和初始化向量
    skcipher_request_set_crypt(req, &sg, &sg, count + pre_len, ivdata);

    // 开始加密
    // 将位于上一分段的数据保护在prefix中，防止被二次加密
    memcpy(prefix, buf, pre_len);
    crypto_skcipher_encrypt(req);
    memcpy(buf, prefix, pre_len);
    // 将数据移到用户态，释放内核态空间
    copy_to_user((void *)ubuf, buf + pre_len, count);
    kfree(buf);
    // 清空本次处理的内存，释放空间
    skcipher_request_free(req);
    crypto_free_skcipher(skcipher);
}
