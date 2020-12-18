#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint-gcc.h>

#include "disk.h"

#define ROOT_DIR_INDEX 2
#define DIR_ITEM_SIZE 128
#define INODE_COUNT 1024
#define BLOCK_COUNT 4096
#define INODE_SIZE 32
#define TYPE_FILE 0
#define TYPE_DIR 1
#define VALID 1
#define INVALID 0
#define MAX_BLOCK_POINT 6


typedef struct super_block{
    int32_t magic_num;
    int32_t free_block_count;
    int32_t free_inode_count;
    int32_t dir_inode_count;
    uint32_t block_map[128];
    uint32_t inode_map[32];
    int32_t unused_data[92];
} sp_block;

// inode: 32 + 16 + 16 + 192 = 256 Bit each
// Total 1024 inodes allocate 1024 * (256 / 8) / 512 = 64 Blocks
// From Block 1 to Block 64
typedef struct{
    uint32_t size;
    uint16_t file_type;
    uint16_t link;
    //-1代表无效，0-4095代表相应的数据块
    uint32_t block_point[6];
} inode;

typedef struct{
    uint32_t inode_id;
    uint16_t valid;
    uint8_t type;
    char name[121];
} dir_item;

/**
 * @brief 计算以2为底的对数，用于地址转换
 * 
 * @param n 
 * @return int 
 */
int lg2(int n) {
    int k = 0;
    while (n > 1) {
        k++;
        n = n >> 1;
    }
    return k;
}

/**
 * @brief 对输入的char*类型路径做分割，分割结果保存在char*类型的数组，返回路径中元素个数(目前不需要申请内存)
 * 
 * @param path_in 
 * @param path_out 
 * @return uint32_t 
 */
uint32_t parse_path(char *path_in, char **path_out) {
    uint32_t len = strlen(path_in);
    uint32_t i;
    uint32_t prev_ptr = 0;
    uint32_t return_data = 0;
    uint32_t cur_len = 0;

    // path_out = (char **)calloc(32, sizeof(char *));
    // for (int i = 0; i < 32; i++) {
    //     path_out[i] = (char *)calloc(32, sizeof(char));
    // }
    
    if (path_in[len-1] == '\n') {
        path_in[len-1] = '\0';
        len--;
    }

    char *ptr = strchr(path_in, '/');
    if (ptr == NULL) {
        strcpy(path_out[0], path_in);
        // printf("parsed result: %s\n", path_out[return_data]);
        return 1;
    }
    if (ptr - path_in == 0 && len == 1) {
        path_out[0] = "/";
        // printf("parsed result: %s\n", path_out[return_data]);
        return 1;
    }
    for (i = 0; i < len; i++) {
        if (path_in[i] == '/' && i == 0) {
            //首先判断：若地址第一个字符为"/"，则为绝对路径，将"/"写到结果的第一栏作为标记
            path_out[return_data] = "/";
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            prev_ptr = 1;
            continue;
        } else if (path_in[i] == '/' && i == len - 1) {
            memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
            path_out[return_data][cur_len] = '\0';
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            return return_data;
        } else if (i == len - 1) {
            cur_len++;
            memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
            path_out[return_data][cur_len] = '\0';
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            return return_data;
        } else if (path_in[i] == '/') {
            memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
            path_out[return_data][cur_len] = '\0';
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            prev_ptr = i + 1;
            cur_len = 0;
            continue;
        } else {
            cur_len++;
            continue;
        }
    }
}

uint32_t parse_args(char *path_in, char **path_out) {
    uint32_t len = strlen(path_in);
    uint32_t i;
    uint32_t prev_ptr = 0;
    uint32_t return_data = 0;
    uint32_t cur_len = 0;

    // path_out = (char **)calloc(32, sizeof(char *));
    // for (int i = 0; i < 32; i++) {
    //     path_out[i] = (char *)calloc(32, sizeof(char));
    // }
    
    if (path_in[len-1] == '\n') {
        path_in[len-1] = '\0';
        len--;
    }

    char *ptr = strchr(path_in, ' ');
    if (ptr == NULL) {
        strcpy(path_out[0], path_in);
        // printf("parsed result: %s\n", path_out[return_data]);
        return 1;
    }
    if (ptr - path_in == 0 && len == 1) {
        printf("no args\n");
        return 0;
    }
    for (i = 0; i < len; i++) {
        //情况：
        //1. 空格，且前面无字符：跳过
        //2. 空格，且前面有字符：写一个arg
        //3. 非空格，且前面有字符：++
        //4. 文件尾情况：需要记录最后一个非空格的字符位置，并写
        //5. 跳过空格后，第一个非空格字符：++
        if (path_in[i] == ' ' && cur_len == 0) {
            prev_ptr++;
            continue;
        } else if (path_in[i] == ' ' && i == len - 1) {
            if (cur_len == 0) {
                return return_data;
            } else {
                memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
                path_out[return_data][cur_len] = '\0';
                // printf("parsed result: %s\n", path_out[return_data]);
                return_data++;
                return return_data;
            }
            return return_data;
        } else if (i == len - 1) {
            cur_len++;
            memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
            path_out[return_data][cur_len] = '\0';
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            return return_data;
        } else if (path_in[i] == ' ' && cur_len != 0) {
            memcpy(path_out[return_data], path_in+prev_ptr, cur_len);
            path_out[return_data][cur_len] = '\0';
            // printf("parsed result: %s\n", path_out[return_data]);
            return_data++;
            prev_ptr = i + 1;
            cur_len = 0;
            continue;
        } else {
            cur_len++;
            continue;
        }
    }
}

/**
 * @brief 将data(大小为1024 byte)写入到指定的数据块中。完成两次对磁盘的写操作。不检查map!
 * 
 * @param data 大小为1K，不检查大小，传入时需确保大小为1K避免段错误!
 * @param file_blockno 数据块号
 * @return int 写入成功返回0，写入失败返回-1
 */
int write_fileblock(char* data, int file_blockno) {
    char *buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char));
    memcpy(buf, data, DEVICE_BLOCK_SIZE);
    if (disk_write_block(2*file_blockno, buf) == -1)
        return -1;
    memcpy(buf, (char *)((char *)data + DEVICE_BLOCK_SIZE), DEVICE_BLOCK_SIZE);
    if (disk_write_block(2*file_blockno+1, buf) == -1)
        return -1;
    free(buf);
    return 0;
}

/**
 * @brief 读取数据块号，返回长度为1024的*char。完成两次对磁盘的读操作
 * 
 * @param file_blockno 数据块号
 * @return char* 读取失败返回NULL
 */
char *read_fileblock(int file_blockno) {
    char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
    if (disk_read_block(2*file_blockno, buf) == -1) {
        printf("Read block %x failed\n", 2*file_blockno);
        return NULL;
    }
    if (disk_read_block(2*file_blockno+1, buf+DEVICE_BLOCK_SIZE) == -1) {
        printf("Read block %x failed\n", 2*file_blockno+1);
        return NULL;
    }
    return buf;
}

/**
 * @brief 根据传入的inode号计算该inode所在的磁盘块号和所在磁盘块的偏移
 * inode size: 32 Bytes = 256 bit
 * block size: 512 Bytes = 4096 bit 
 * each block has: 512/32 = 16 inodes
 * total inodes: 32 * 32 = 1024
 * total inodes allocate blocks: 1024 * 32B / 512B = 64 Blocks
 * block 0 & block 1 for superblock, so block 2 ~ block 65 for inodes
 * so :
 * blockno = inode_id / 16 + 2;
 * offset = (inode_id % 16) * 32 
 * 
 * 
 * @param inode_id inode号
 * @param blockno 磁盘块号
 * @param offset 磁盘块内偏移地址
 */
void count_inode_block(int inode_id, int *blockno, int *offset) {
    *blockno = ((inode_id >> lg2(DEVICE_BLOCK_SIZE / INODE_SIZE)) & 0x3f) + 2;
    *offset = (inode_id & 0x0f) << lg2(INODE_SIZE);
}

/**
 * @brief 给定超级块信息（已分配内存的指针），从头开始查找block map，
 * 若找到空闲块则将对应block map置1，并返回对应的file_blockno
 * 
 * @param sp_ptr 注意指针需为有效指针
 * @return uint32_t 分配成功返回blockno，分配失败返回-1
 */
uint32_t allocate_new_block(sp_block *sp_ptr) {
    //Block 0 to Block 32为保留数据，因此直接从1开始
    if (sp_ptr->free_block_count == 0) {
        printf("no enough free block!\n");
        return -1;
    }
    uint32_t mask;
    uint32_t blockno;
    for (int i = 1; i < 128; i++) {
        for (int j = 0; j < 32; j++) {
            mask = 1 << (31 - j);
            // printf("%d\n", sp_ptr->block_map[i] & mask);
            // uint32_t result = sp_ptr->block_map[i] & mask;
            if ((sp_ptr->block_map[i] & mask) == 0) {
                //查找到空块
                blockno = 32 * i + j;
                sp_ptr->block_map[i] = sp_ptr->block_map[i] | mask;
                sp_ptr->free_block_count--;
                printf("Block %d allocated\n", blockno);
                return blockno;
            }
        }
    }
    return -1;
}

/**
 * @brief 给定超级块信息（已分配内存的指针）和数据块号，在超级块map中释放该块。
 * 
 * @param sp_ptr 注意需要为有效指针
 * @param blockno 
 * @return uint32_t 释放成功返回0，释放失败返回-1
 */
uint32_t free_block(sp_block *sp_ptr, uint32_t blockno) {
    uint32_t mask = 1 << (31 - (blockno % 32));
    // printf("mask: %d\n", mask);
    if ((sp_ptr->block_map[blockno / 32] & mask) == 0) {
        printf("block already free\n");
        return -1;
    }
    sp_ptr->block_map[blockno / 32] = sp_ptr->block_map[blockno / 32] & (~mask);
    sp_ptr->free_block_count++;
    printf("Block %d free\n", blockno);
    return 0;
} 

/**
 * @brief 对超级块进行初始化(格式化)
 * 
 */
void init_superblock() {
    // char *sp_buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char));
    sp_block *sp_ptr = (sp_block *)calloc(1, sizeof(sp_block));
    sp_ptr->magic_num = 0x97ec6587;
    sp_ptr->free_block_count = 4063;
    sp_ptr->free_inode_count = 1024;
    sp_ptr->dir_inode_count = 0;
    memset(sp_ptr->block_map, 0, sizeof(sp_ptr->block_map));
    //block map的0~32要置1
    memset(sp_ptr->block_map, -1, 4);
    sp_ptr->block_map[1] = 0x80000000;

    memset(sp_ptr->inode_map, 0, sizeof(sp_ptr->inode_map));
    memset(sp_ptr->unused_data, -1, sizeof(sp_ptr->unused_data));
    write_fileblock((char*) sp_ptr, 0);
    free(sp_ptr);
}


/**
 * @brief 读取磁盘超级块数据
 * 
 * @return sp_block* 若超级块数据有效，则返回指向超级块结构体的指针;
 * 若超级块数据无效，则返回NULL指针
 */
sp_block *read_superblock_data() {
    sp_block *sp_ptr = (sp_block *)calloc(1, sizeof(sp_block));
    sp_ptr = (sp_block *)read_fileblock(0);
    if (sp_ptr->magic_num != 0x97ec6587) {
        printf("Magic number invalid!\n");
        return NULL;
    }
    return sp_ptr;
}

/**
 * @brief 将给定的数据写入超级块中
 * 
 * @param sp_ptr 指向超级块结构体的指针
 * @return 写入成功返回0,否则返回-1
 */
int write_superblock_data(sp_block *sp_ptr) {
    // char *buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char));
    // memcpy(buf, sp_ptr, DEVICE_BLOCK_SIZE);
    // if (disk_write_block(0, buf) == -1)
    //     return -1;
    // memcpy(buf, (char *)((char *)sp_ptr + DEVICE_BLOCK_SIZE), DEVICE_BLOCK_SIZE);
    // if (disk_write_block(0, buf) == -1)
    //     return -1;
    // return 0;
    if (write_fileblock((char *)sp_ptr, 0) == -1)
        return -1;
    // free(sp_ptr);
    return 0;
}

/**
 * @brief 返回inode_id所对应的inode的信息
 * 
 * @param inode_id 
 * @return inode* 
 */
inode* read_inode(uint32_t inode_id) {
    int blockno;
    int offset;
    char *buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char)); 
    count_inode_block(inode_id, &blockno, &offset);
    disk_read_block(blockno, buf);
    inode *inode_return = (inode *)calloc(1, sizeof(inode));
    memcpy(inode_return, buf + offset, sizeof(inode));
    free(buf);
    return inode_return;
}

/**
 * @brief 修改对应inode_id处的inode
 * 
 * @param inode_in 
 * @param inode_id 
 * @return uint32_t 若写失败返回-1，成功返回0
 */
uint32_t edit_inode(inode* inode_in, uint32_t inode_id) {
    int blockno, offset;
    count_inode_block(inode_id, &blockno, &offset);
    char *buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char));
    disk_read_block(blockno, buf);
    memcpy(buf + offset, inode_in, INODE_SIZE);
    if (disk_write_block(blockno, buf) == -1) {
        printf("Write inode block error!\n");
        return -1;
    }
    free(buf);
    // free(inode_in);
    return 0;
}

/**
 * @brief 删除一个inode，注意：实际上只是将map对应位置置零，以减少读写次数，需传入有效的sp_ptr
 * 
 * @param sp_ptr
 * @param inode_id 
 * @return uint32_t 若删除成功返回0，失败返回-1
 */
uint32_t remove_inode(sp_block *sp_ptr, uint32_t inode_id) {
    // sp_block *sp_ptr = (sp_block *)calloc(1, sizeof(sp_block));
    // sp_ptr = read_superblock_data();
    int blockno, offset;
    count_inode_block(inode_id, &blockno, &offset);
    int mask = 1 << (31 - (inode_id & 0x1f));
    if (sp_ptr->inode_map[inode_id >> 5] & mask == 0) {
        printf("inode not exist!\n");
        return -1;
    } else {
        sp_ptr->inode_map[inode_id >> 5] = sp_ptr->inode_map[inode_id >> 5] & ~mask;
        sp_ptr->free_inode_count++;
        // if (write_superblock_data(sp_ptr) == -1) {
        //     printf("write superblock failed!\n");
        //     return -1;
        // }
        // free(sp_ptr);
        return 0;
    }

}

/**
 * @brief 用于新建inode, 将对应的inode写入空闲的块中，返回写入的inode id
 * 
 * @param inode_in 
 * @param sp_ptr 需要提供有效的sp_block指针
 * @return 写入正常时返回inode_id，写入失败返回-1
 */
uint32_t write_new_inode(inode *inode_in, sp_block *sp_ptr) {
    // sp_block *sp_ptr = (sp_block *)calloc(1, sizeof(sp_block));
    // sp_ptr = read_superblock_data();
    if (sp_ptr->free_inode_count == 0) {
        printf("No enough space for new inode!\n");
        return -1;
    }
    int size = INODE_COUNT / INODE_SIZE;
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < INODE_SIZE; j++) {
            uint32_t mask = 1 << (31 - j);
            if ((mask & sp_ptr->inode_map[i]) == 0) {
                //发现空位
                uint32_t inode_id = i * INODE_SIZE + j;
                if (edit_inode(inode_in, inode_id) == -1) {
                    return -1;
                }
                sp_ptr->free_inode_count--;
                sp_ptr->inode_map[i] = sp_ptr->inode_map[i] | mask;
                // if (write_superblock_data(sp_ptr) == -1) {
                //     printf("Write superblock error!\n");
                //     return -1;
                // }
                // free(sp_ptr);
                return inode_id;

            } 
        }    
    }
}

/**
 * @brief 返回对应inode指向的文件。若文件大于1块，则连接后一并返回
 * 
 * @param inode_in 
 * @return char* 指向文件的指针
 */
char *read_file(inode* inode_in) {
    int block = 6;
    for (int i = 0; i < MAX_BLOCK_POINT; i++) {
        if (inode_in->block_point[i] == -1) {
            block = i;
            break;
        }
    }
    char *read_buf = (char *)calloc(DEVICE_BLOCK_SIZE * 2 * block, sizeof(char));
    char *read_ptr;
    for (int i = 0; i < block; i++) {
        //定义：1个文件块 = 2个磁盘块，
        //磁盘Block 66 ~ Block 8191分配到数据块File 0 to File 4095
        //实际上只有(8191 - 66 + 1) / 2 = 4063个数据块是有效的
        // read_buf = read_fileblock(inode_in->block_point[i]);
        read_ptr = read_fileblock(inode_in->block_point[i]);
        memcpy(read_buf, read_ptr, DEVICE_BLOCK_SIZE * 2);
        free(read_ptr);
        // printf("%.2x%.2x\n", read_buf[6], read_buf[7]);
        read_buf += (DEVICE_BLOCK_SIZE * 2);
    }
    read_buf = read_buf - DEVICE_BLOCK_SIZE * 2 * block;
    read_buf[inode_in->size] == '\0';
    // printf("%.2x%.2x\n", read_buf[6], read_buf[7]);
    return read_buf;
}

/**
 * @brief 将指定数据write_data写入到inode_in对应的文件中，注意sp_ptr指针需为有效指针，注意调用完后写inode！
 * 
 * @param sp_ptr
 * @param inode_in 
 * @param write_data 
 * @return uint32_t 写入成功返回0，写入失败返回-1
 */
uint32_t write_file(sp_block *sp_ptr, inode* inode_in, char *write_data) {
    int block = 6;
    for (int i = 0; i < MAX_BLOCK_POINT; i++) {
        if (inode_in->block_point[i] == -1) {
            block = i;
            break;
        }
    }
    int file_len;
    if (inode_in->file_type == TYPE_DIR) {
        file_len = inode_in->size;
    } else {
        file_len = strlen(write_data);
    }
    // int file_len = strlen(write_data);
    if (file_len >= 6 * 2 * DEVICE_BLOCK_SIZE) {
        printf("write data too long!\n");
        return -1;
    }
    inode_in->size = file_len;
    int new_block_count = file_len / (2 * DEVICE_BLOCK_SIZE) + 1;
    if (new_block_count > block) {
        //新数据需要分配更多的数据块
        for (int i = block; i < new_block_count; i++) {
            int new_blockno = allocate_new_block(sp_ptr);
            if (new_blockno == -1) {
                printf("allocate new block failed\n");
                return -1;
            }
            inode_in->block_point[i] = new_blockno;
        }
    } else if (new_block_count < block) {
        //新数据需要分配更少的数据块
        for (int i = new_block_count; i < block; i++) {
            free_block(sp_ptr, inode_in->block_point[i]);
            inode_in->block_point[i] = -1;
        }
    } else {
        //新数据需要分配和原本一样的数据块
    }
    // char *buf = (char *)calloc(DEVICE_BLOCK_SIZE * 2, sizeof(char));
    char *buf;
    int ptr = 0;
    int file_len_const = file_len;
    for (int i = 0; i < new_block_count; i++) {
        buf = (char *)calloc(DEVICE_BLOCK_SIZE * 2, sizeof(char));
        ptr = (file_len < 2 * DEVICE_BLOCK_SIZE) ? file_len : (2 * DEVICE_BLOCK_SIZE);
        if (file_len > 2 * DEVICE_BLOCK_SIZE) {
            file_len -= (2 * DEVICE_BLOCK_SIZE);
        } 
        memcpy(buf, write_data + (2 * i * DEVICE_BLOCK_SIZE), ptr);
        if (i == new_block_count - 1) {
            buf[file_len] = '\0';
        }
        write_fileblock(buf, inode_in->block_point[i]);
        free(buf);
    }
    // write_superblock_data(sp_ptr);
    return 0;
}


int init_root_dir() {
    //仅在无数据，初始化磁盘时使用
    //步骤:create root inode, create root dir file
    sp_block *sp_ptr = (sp_block *)calloc(1, sizeof(sp_block));
    sp_ptr = read_superblock_data();
    //固定根目录的索引号为2
    inode root_inode;
    //根目录初始含(.), (..)两项,分配两项的空间
    root_inode.size = 2 * DIR_ITEM_SIZE;
    root_inode.file_type = TYPE_DIR;
    root_inode.link = 1;
    memset(root_inode.block_point, -1, sizeof(root_inode.block_point));
    root_inode.block_point[0] = 33;

    //写inode
    uint32_t mask = 1 << (31 - ROOT_DIR_INDEX);
    uint32_t inode_id = ROOT_DIR_INDEX;
    if (edit_inode(&root_inode, inode_id) == -1) {
        printf("Write inode failed!\n");
        return -1;
    }

    //写目录项
    dir_item dir_dot;
    dir_dot.inode_id = inode_id;
    dir_dot.valid = VALID;
    dir_dot.type = TYPE_DIR;
    memcpy(dir_dot.name, ".", sizeof(dir_dot.name));

    dir_item dir_2dot;
    dir_2dot.inode_id = inode_id;
    dir_2dot.valid = VALID;
    dir_2dot.type = TYPE_DIR;
    memcpy(dir_2dot.name, "..", sizeof(dir_2dot.name));

    char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
    memcpy(buf, &dir_dot, sizeof(dir_item));
    memcpy(buf + sizeof(dir_item), &dir_2dot, sizeof(dir_item));
    uint32_t mask2 = 0x40000000;
    if (write_fileblock(buf, 33) == -1) {
        printf("Write dir item failed!\n");
        return -1;
    }
    free(buf);

    //写超级块
    sp_ptr->free_inode_count--;
    sp_ptr->free_block_count--;
    sp_ptr->dir_inode_count++;

    sp_ptr->inode_map[0] = sp_ptr->inode_map[0] | mask;
    sp_ptr->block_map[1] = sp_ptr->block_map[1] | mask2;
    if (write_superblock_data(sp_ptr) == -1) {
        printf("Write superblock failed!\n");
        return -1;
    }

    return 0;
}

/**
 * @brief 在给定的目录类型inode中寻找名字为name，类型为type的文件/目录
 * 
 * @param dir_inode 
 * @param name 
 * @param type 
 * @return uint32_t 若找到则返回inode_no，若找不到则返回-1
 */
uint32_t search_in_dir(inode *dir_inode, char *name, int type) {
    if (dir_inode->file_type != TYPE_DIR) {
        printf("invalid inode!\n");
        return -1;
    }
    char *dir_data = read_file(dir_inode);
    dir_item *dir_ptr = (dir_item *)calloc(1, sizeof(dir_item));
    int count = dir_inode->size / DIR_ITEM_SIZE;
    if (count == 0) {
        printf("empty directory!\n");
        return -1;
    }
    for (int i = 0; i < count; i++) {
        memcpy(dir_ptr, (dir_item *)(dir_data + i * DIR_ITEM_SIZE), DIR_ITEM_SIZE);
        if (!strcmp(name, dir_ptr->name) && (type == dir_ptr->type) && (dir_ptr->valid == VALID)) {
            //find item!
            free(dir_data);
            return dir_ptr->inode_id;
        }
    }
    // not found
    return -1;
}

/**
 * @brief 根据当前目录、分词后的目录结果找到需要的目录/文件inode，找到返回inode号，找不到返回-1
 * 
 * @param cur_path_inode_no 
 * @param parsed_path 
 * @param path_count 
 * @return uint32_t 
 */
uint32_t find_inode_by_path(uint32_t src_path_inode_no, char **parsed_path, uint32_t path_count, uint32_t type) {
    uint32_t dest_inode_no = -1;
    inode *cur_inode = (inode *)calloc(1, sizeof(inode));
    uint32_t cur_inode_no = src_path_inode_no;
    if (type != TYPE_DIR && type != TYPE_FILE) {
        printf("Invalid type!\n");
        return -1;
    }
    if (path_count == 0) {
        printf("path too short!\n");
        return -1;
    }
    if (path_count == 1) {
        if (!strcmp(parsed_path[0], "/") && type == TYPE_DIR) {
            return ROOT_DIR_INDEX;
        } else {
            cur_inode = read_inode(cur_inode_no);
            dest_inode_no = search_in_dir(cur_inode, parsed_path[0], type);
            if (dest_inode_no != -1) {
                return dest_inode_no;
            }
        }
        return -1;
    }

    for (int i = 0; i < path_count; i++) {
        if (i == 0 && !strcmp(parsed_path[0], "/")) {
            cur_inode = read_inode(ROOT_DIR_INDEX);
        } else {
            cur_inode = read_inode(cur_inode_no);
        }

        if (i == path_count - 1) {
            dest_inode_no = search_in_dir(cur_inode, parsed_path[i], type);
            if (dest_inode_no != -1) {
                return dest_inode_no;
            }
            return -1;
        }
        cur_inode_no = search_in_dir(cur_inode, parsed_path[i], TYPE_DIR);
        if (cur_inode_no == -1) {
            printf("path not found");
            return -1;
        }
        
    }
}

/**
 * @brief 在指定的目录(提供inode数据)下新建名字为name的目录，返回新建目录的inode号
 * 
 * @param cur_dir 
 * @param name 
 * @return uint32_t 建立成功返回新目录的inode号，建立失败返回-1
 */
uint32_t make_dir(uint32_t cur_dir_inode_id, char *name) {
    inode *cur_dir = read_inode(cur_dir_inode_id);
    if (cur_dir->file_type != TYPE_DIR) {
        printf("invalid inode!\n");
        return -1;
    }
    sp_block *sp_ptr = read_superblock_data();
    if (sp_ptr->free_block_count == 0) {
        printf("not enough free block!");
        return -1;
    }
    if (sp_ptr->free_inode_count == 0) {
        printf("not enough free inode!");
        return -1;
    }
    //增加：同名目录检测
    if (search_in_dir(cur_dir, name, TYPE_DIR) != -1) {
        printf("directory already exist!\n");
        return -1;
    }
    if (!strcmp(name, "/")) {
        printf("invalid name!\n");
        return -1;
    }
    int block = 6;
    int dir_item_count = cur_dir->size / DIR_ITEM_SIZE;
    for (int i = 0; i < MAX_BLOCK_POINT; i++) {
        if (cur_dir->block_point[i] == -1) {
            block = i;
            break;
        } 
    }
    if (block == MAX_BLOCK_POINT && dir_item_count == MAX_BLOCK_POINT * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("dir item full!\n");
        return -1;
    } else if (dir_item_count == block * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("need to allocate new block for new dir item\n");
        //原目录块已满，需要分配新目录块的情况：
        //步骤：
        //1. 检查是否剩余多于两个空闲磁盘块（一个分配给原目录，一个分配给新建的目录）
        if (sp_ptr->free_block_count < 2) {
            printf("no enough free block!\n");
            return -1;
        }
        //2. 首先增加原目录：读超级块，查找block_map，并分配，超级块free--
        uint32_t cur_dir_new_blockno = allocate_new_block(sp_ptr);
        if (cur_dir_new_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        //3. 改变原目录inode，block_point增加对新块的链接，size增加，写原目录inode
        cur_dir->block_point[block] = cur_dir_new_blockno;
        cur_dir->size += DIR_ITEM_SIZE;
        edit_inode(cur_dir, cur_dir_inode_id);
        //4. 为新目录分配inode，写新目录inode
        inode *new_dir_inode = (inode *)calloc(1, sizeof(inode));
        new_dir_inode->file_type = TYPE_DIR;
        new_dir_inode->link = 1;
        new_dir_inode->size = 2 * DIR_ITEM_SIZE;
        uint32_t new_dir_blockno = allocate_new_block(sp_ptr);
        if (new_dir_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        memset(new_dir_inode->block_point, -1, sizeof(new_dir_inode->block_point));
        new_dir_inode->block_point[0] = new_dir_blockno;
        uint32_t new_dir_inode_id = write_new_inode(new_dir_inode, sp_ptr);
        if (new_dir_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //5. 写新目录目录项，初始化.为自身，..为上一级目录，写入数据块到磁盘中
        dir_item dir_dot;
        dir_dot.inode_id = new_dir_inode_id;
        dir_dot.valid = VALID;
        dir_dot.type = TYPE_DIR;
        memcpy(dir_dot.name, ".", sizeof(dir_dot.name));

        dir_item dir_2dot;
        dir_2dot.inode_id = cur_dir_inode_id;
        dir_2dot.valid = VALID;
        dir_2dot.type = TYPE_DIR;
        memcpy(dir_2dot.name, "..", sizeof(dir_2dot.name));

        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        memcpy(buf, &dir_dot, sizeof(dir_item));
        memcpy(buf + sizeof(dir_item), &dir_2dot, sizeof(dir_item));
        if (write_fileblock(buf, new_dir_blockno) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);

        //6. 写原目录目录项，新增新目录相关内容，写入数据块到磁盘中
        dir_item new_dir;
        new_dir.inode_id = new_dir_inode_id;
        new_dir.valid = VALID;
        new_dir.type = TYPE_DIR;
        memcpy(new_dir.name, name, sizeof(new_dir.name));
        buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        memcpy(buf, &new_dir, sizeof(dir_item));
        if (write_fileblock(buf, cur_dir_new_blockno) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //7. 写超级块
        sp_ptr->dir_inode_count++;
        write_superblock_data(sp_ptr);
        return new_dir_inode_id;
    } else {
        //不需要分配新目录块的情况：
        //步骤：
        //1. 为新目录分配inode，写新目录inode
        inode *new_dir_inode = (inode *)calloc(1, sizeof(inode));
        uint32_t new_dir_blockno = allocate_new_block(sp_ptr);
        if (new_dir_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        memset(new_dir_inode->block_point, -1, sizeof(new_dir_inode->block_point));
        new_dir_inode->block_point[0] = new_dir_blockno;
        new_dir_inode->file_type = TYPE_DIR;
        new_dir_inode->link = 1;
        new_dir_inode->size = 2 * DIR_ITEM_SIZE;
        uint32_t new_dir_inode_id = write_new_inode(new_dir_inode, sp_ptr);
        if (new_dir_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //2. 写新目录目录项，初始化，写入数据块到磁盘
        dir_item dir_dot;
        dir_dot.inode_id = new_dir_inode_id;
        dir_dot.valid = VALID;
        dir_dot.type = TYPE_DIR;
        memcpy(dir_dot.name, ".", sizeof(dir_dot.name));

        dir_item dir_2dot;
        dir_2dot.inode_id = cur_dir_inode_id;
        dir_2dot.valid = VALID;
        dir_2dot.type = TYPE_DIR;
        memcpy(dir_2dot.name, "..", sizeof(dir_2dot.name));

        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        memcpy(buf, &dir_dot, sizeof(dir_item));
        memcpy(buf + sizeof(dir_item), &dir_2dot, sizeof(dir_item));
        if (write_fileblock(buf, new_dir_blockno) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //3. 写原目录inode，size增加
        uint32_t ptr = cur_dir->size - (block - 1) * 2 * DEVICE_BLOCK_SIZE;
        cur_dir->size += DIR_ITEM_SIZE;
        edit_inode(cur_dir, cur_dir_inode_id);
        //4. 写原目录目录项，计算偏移，写入新目录相关内容，写入数据块到磁盘
        dir_item new_dir;
        new_dir.inode_id = new_dir_inode_id;
        new_dir.valid = VALID;
        new_dir.type = TYPE_DIR;
        memcpy(new_dir.name, name, sizeof(new_dir.name));
        buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        buf = read_fileblock(cur_dir->block_point[block-1]);
        memcpy(buf+ptr, &new_dir, sizeof(dir_item));
        if (write_fileblock(buf, cur_dir->block_point[block-1]) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //5. 写入超级块
        sp_ptr->dir_inode_count++;
        write_superblock_data(sp_ptr);
        return new_dir_inode_id;
    }
    
}

/**
 * @brief 输入目录的inode_id，在stdout输出所有目录项。
 * 
 * @param dir_inode_id 
 */
void list_dir(uint32_t dir_inode_id) {
    inode *dir_inode = (inode *)calloc(1, sizeof(inode));
    dir_inode = read_inode(dir_inode_id);
    if (dir_inode->file_type != TYPE_DIR) {
        printf("not a directory\n");
        return;
    }
    uint32_t item_count = dir_inode->size / DIR_ITEM_SIZE;
    char *buf = read_file(dir_inode);
    dir_item *dir_ptr = (dir_item *)calloc(1, sizeof(dir_item));
    for (int i = 0; i < dir_inode->size; i+=DIR_ITEM_SIZE) {
        memcpy(dir_ptr, buf + i, sizeof(dir_item));
        if (dir_ptr->type == TYPE_FILE)
            printf("FILE\t");
        else if (dir_ptr->type == TYPE_DIR)
            printf("DIR \t");
        else {
            printf("unknown type\n");
            return;
        }
        printf("%s", dir_ptr->name);
        printf("\n");
    }
    
    
}

/**
 * @brief 在指定的目录(inode id)下新建名字为name的文件，返回新建文件的inode id
 * 
 * @param cur_dir_inode_id 
 * @param name 
 * @return uint32_t 建立成功返回新文件的inode号，建立失败返回-1
 */
uint32_t make_file(uint32_t cur_dir_inode_id, char *name) {
    inode *cur_dir = read_inode(cur_dir_inode_id);
    if (cur_dir->file_type != TYPE_DIR) {
        printf("invalid inode!\n");
        return -1;
    }
    sp_block *sp_ptr = read_superblock_data();
    if (sp_ptr->free_block_count == 0) {
        printf("not enough free block!");
        return -1;
    }
    if (sp_ptr->free_inode_count == 0) {
        printf("not enough free inode!");
        return -1;
    }
    //增加：同名文件检测
    if (search_in_dir(cur_dir, name, TYPE_FILE) != -1) {
        printf("file already exist!\n");
        return -1;
    }
    if (!strcmp(name, "/")) {
        printf("invalid name!\n");
        return -1;
    }
    int block = 6;
    int dir_item_count = cur_dir->size / DIR_ITEM_SIZE;
    for (int i = 0; i < MAX_BLOCK_POINT; i++) {
        if (cur_dir->block_point[i] == -1) {
            block = i;
            break;
        } 
    }
    if (block == MAX_BLOCK_POINT && dir_item_count == MAX_BLOCK_POINT * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("dir item full!\n");
        return -1;
    } else if (dir_item_count == block * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("need to allocate new block for new dir item\n");
        //原目录块已满，需要分配新目录块的情况：
        //步骤：
        //1. 检查是否剩余多于两个空闲磁盘块（一个分配给原目录，一个分配给新建的目录）
        if (sp_ptr->free_block_count < 2) {
            printf("no enough free block!\n");
            return -1;
        }
        //2. 首先增加原目录：读超级块，查找block_map，并分配
        uint32_t cur_dir_new_blockno = allocate_new_block(sp_ptr);
        if (cur_dir_new_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        //3. 改变原目录inode，block_point增加对新块的链接，size增加，写原目录inode
        cur_dir->block_point[block] = cur_dir_new_blockno;
        cur_dir->size += DIR_ITEM_SIZE;
        edit_inode(cur_dir, cur_dir_inode_id);
        //4. 为新文件分配inode，写新文件inode
        inode *new_file_inode = (inode *)calloc(1, sizeof(inode));
        new_file_inode->file_type = TYPE_FILE;
        new_file_inode->link = 1;
        new_file_inode->size = 0;
        uint32_t new_file_blockno = allocate_new_block(sp_ptr);
        if (new_file_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        memset(new_file_inode->block_point, -1, sizeof(new_file_inode->block_point));
        new_file_inode->block_point[0] = new_file_blockno;
        uint32_t new_file_inode_id = write_new_inode(new_file_inode, sp_ptr);
        if (new_file_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //5. 空文件，无需写
        //6. 写原目录目录项，新增新文件相关内容，写入数据块到磁盘中
        dir_item new_file;
        new_file.inode_id = new_file_inode_id;
        new_file.valid = VALID;
        new_file.type = TYPE_FILE;
        memcpy(new_file.name, name, sizeof(new_file.name));
        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        memcpy(buf, &new_file, sizeof(dir_item));
        if (write_fileblock(buf, cur_dir_new_blockno) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //7. 写超级块
        write_superblock_data(sp_ptr);
        return new_file_inode_id;
    } else {
        //不需要分配新目录块的情况：
        //步骤：
        //1. 为新文件分配inode，写新文件inode
        inode *new_file_inode = (inode *)calloc(1, sizeof(inode));
        uint32_t new_file_blockno = allocate_new_block(sp_ptr);
        if (new_file_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        memset(new_file_inode->block_point, -1, sizeof(new_file_inode->block_point));
        new_file_inode->block_point[0] = new_file_blockno;
        new_file_inode->file_type = TYPE_FILE;
        new_file_inode->link = 1;
        new_file_inode->size = 0;
        uint32_t new_file_inode_id = write_new_inode(new_file_inode, sp_ptr);
        if (new_file_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //2. 写新文件：为空，无需写
        //3. 写原目录inode，size增加
        uint32_t ptr = cur_dir->size - (block - 1) * 2 * DEVICE_BLOCK_SIZE;
        cur_dir->size += DIR_ITEM_SIZE;
        edit_inode(cur_dir, cur_dir_inode_id);
        //4. 写原目录目录项，计算偏移，写入新目录相关内容，写入数据块到磁盘
        dir_item new_file;
        new_file.inode_id = new_file_inode_id;
        new_file.valid = VALID;
        new_file.type = TYPE_FILE;
        memcpy(new_file.name, name, sizeof(new_file.name));
        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        buf = read_fileblock(cur_dir->block_point[block-1]);
        memcpy(buf+ptr, &new_file, sizeof(dir_item));
        if (write_fileblock(buf, cur_dir->block_point[block-1]) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //5. 写入超级块
        write_superblock_data(sp_ptr);
        return new_file_inode_id;
    }
}

/**
 * @brief 将指定的文件(file_inode_id)复制到指定的目录(dest_dir_inode_id)中
 * 
 * @param file_name
 * @param file_inode_id 
 * @param dest_dir_inode_id 
 * @return uint32_t 返回复制文件的inode no
 */
uint32_t move_file(char *file_name, uint32_t file_inode_id, uint32_t dest_dir_inode_id) {
    inode *file_inode = (inode *)calloc(1, sizeof(inode));
    inode *dest_dir_inode = (inode *)calloc(1, sizeof(inode));
    file_inode = read_inode(file_inode_id);
    dest_dir_inode = read_inode(dest_dir_inode_id);
    if (file_inode->file_type != TYPE_FILE) {
        printf("invalid inode!\n");
        return -1;
    }
    if (dest_dir_inode->file_type != TYPE_DIR) {
        printf("invalid inode!\n");
        return -1;
    }
    sp_block *sp_ptr = read_superblock_data();
    
    if (sp_ptr->free_block_count == 0) {
        printf("not enough free block!");
        return -1;
    }
    if (sp_ptr->free_inode_count == 0) {
        printf("not enough free inode!");
        return -1;
    }
    char *file_data = read_file(file_inode);
    //增加：同名文件检测
    uint32_t exist_file_inodeno = search_in_dir(dest_dir_inode, file_name, TYPE_FILE);
    if (exist_file_inodeno != -1) {
        printf("file already exist!\n");
        //文件已经存在，需要覆盖
        inode *exist_file_inode = (inode *)calloc(1, sizeof(inode));
        write_file(sp_ptr, exist_file_inode, file_data);
        edit_inode(exist_file_inode, exist_file_inodeno);
        return exist_file_inodeno;
        // return -1;
    }

    
    uint32_t file_block_count = file_inode->size / (2 * DIR_ITEM_SIZE) + 1;

    int block = 6;
    int dir_item_count = dest_dir_inode->size / DIR_ITEM_SIZE;
    for (int i = 0; i < MAX_BLOCK_POINT; i++) {
        if (dest_dir_inode->block_point[i] == -1) {
            block = i;
            break;
        } 
    }
    if (block == MAX_BLOCK_POINT && dir_item_count == MAX_BLOCK_POINT * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("dir item full!\n");
        return -1;
    } else if (dir_item_count == block * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
        printf("need to allocate new block for new dir item\n");
        //目标目录块已满，需要分配新目录块的情况：
        //步骤：
        //1. 检查是否剩余多于两个空闲磁盘块（一个分配给目标目录，一个分配给新建的目录）
        if (sp_ptr->free_block_count < (file_block_count + 1)) {
            printf("no enough free block!\n");
            return -1;
        }
        //2. 首先增加目标目录：读超级块，查找block_map，并分配
        uint32_t dest_dir_new_blockno = allocate_new_block(sp_ptr);
        if (dest_dir_new_blockno == -1) {
            printf("allocate new block failed!\n");
            return -1;
        }
        //3. 改变原目录inode，block_point增加对新块的链接，size增加，写原目录inode
        dest_dir_inode->block_point[block] = dest_dir_new_blockno;
        dest_dir_inode->size += DIR_ITEM_SIZE;
        edit_inode(dest_dir_inode, dest_dir_inode_id);
        //4. 为新文件分配inode，写新文件inode
        inode *new_file_inode = (inode *)calloc(1, sizeof(inode));
        new_file_inode->file_type = TYPE_FILE;
        new_file_inode->link = file_inode->link;
        new_file_inode->size = file_inode->size;
        memset(new_file_inode->block_point, -1, sizeof(new_file_inode->block_point));
        for (int i = 0; i < file_block_count; i++) {
            uint32_t new_file_blockno = allocate_new_block(sp_ptr);
            if (new_file_blockno == -1) {
                printf("allocate new block failed\n");
                return -1;
            }
            new_file_inode->block_point[i] = new_file_blockno;
        }
        uint32_t new_file_inode_id = write_new_inode(new_file_inode, sp_ptr);
        if (new_file_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //5. 写新文件
        write_file(sp_ptr, new_file_inode, file_data);
        edit_inode(new_file_inode, new_file_inode_id);
        //6. 写目标目录目录项，新增新文件相关内容，写入数据块到磁盘中
        dir_item new_file;
        new_file.inode_id = new_file_inode_id;
        new_file.valid = VALID;
        new_file.type = TYPE_FILE;
        memcpy(new_file.name, file_name, sizeof(new_file.name));
        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        memcpy(buf, &new_file, sizeof(dir_item));
        if (write_fileblock(buf, dest_dir_new_blockno) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //7. 写超级块
        write_superblock_data(sp_ptr);
        return new_file_inode_id;
    } else {
        //不需要分配新目录块的情况：
        //步骤：
        //1. 为新文件分配inode，写新文件inode
        inode *new_file_inode = (inode *)calloc(1, sizeof(inode));
        new_file_inode->file_type = TYPE_FILE;
        new_file_inode->link = file_inode->link;
        new_file_inode->size = file_inode->size;
        memset(new_file_inode->block_point, -1, sizeof(new_file_inode->block_point));
        for (int i = 0; i < file_block_count; i++) {
            uint32_t new_file_blockno = allocate_new_block(sp_ptr);
            if (new_file_blockno == -1) {
                printf("allocate new block failed\n");
                return -1;
            }
            new_file_inode->block_point[i] = new_file_blockno;
        }
        uint32_t new_file_inode_id = write_new_inode(new_file_inode, sp_ptr);
        if (new_file_inode_id == -1) {
            printf("write new inode failed!\n");
            return -1;
        }
        //2. 写新文件
        write_file(sp_ptr, new_file_inode, file_data);
        //3. 写目标目录inode，size增加
        uint32_t ptr = dest_dir_inode->size - (block - 1) * 2 * DEVICE_BLOCK_SIZE;
        dest_dir_inode->size += DIR_ITEM_SIZE;
        edit_inode(dest_dir_inode, dest_dir_inode_id);
        //4. 写目标目录目录项，计算偏移，写入新目录相关内容，写入数据块到磁盘
        dir_item new_file;
        new_file.inode_id = new_file_inode_id;
        new_file.valid = VALID;
        new_file.type = TYPE_FILE;
        memcpy(new_file.name, file_name, sizeof(new_file.name));
        char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
        buf = read_fileblock(dest_dir_inode->block_point[block-1]);
        memcpy(buf+ptr, &new_file, sizeof(dir_item));
        if (write_fileblock(buf, dest_dir_inode->block_point[block-1]) == -1) {
            printf("write fileblock failed!\n");
            return -1;
        }
        free(buf);
        //5. 写入超级块
        write_superblock_data(sp_ptr);
        return new_file_inode_id;
    }
}

uint32_t ls_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count, TYPE_DIR);
    if (dest_inode_id != -1) {
        list_dir(dest_inode_id);
    }
    free(path_out);

}

uint32_t mkdir_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        make_dir(dest_inode_id, path_out[path_count - 1]);
    }
    free(path_out);
}

uint32_t touch_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        make_file(dest_inode_id, path_out[path_count - 1]);
    }
    free(path_out);
}

uint32_t cp(uint32_t cur_dir_inode_id, char *path_src, char *path_dest) {
    char **path_out_src;
    path_out_src = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out_src[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count_src = parse_path(path_src, path_out_src);
    char **path_out_dest;
    path_out_dest = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out_dest[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count_dest = parse_path(path_dest, path_out_dest);
    uint32_t src_inode_id = find_inode_by_path(cur_dir_inode_id, path_out_src, path_count_src, TYPE_FILE);
    if (src_inode_id != -1) {
        uint32_t dest_dir_inode_id;
        if (path_count_dest == 1) {
            dest_dir_inode_id = cur_dir_inode_id;
        } else {
            dest_dir_inode_id = find_inode_by_path(cur_dir_inode_id, path_out_dest, path_count_dest-1, TYPE_DIR);
        }
        if (dest_dir_inode_id != -1) {
            move_file(path_out_dest[path_count_dest-1], src_inode_id, dest_dir_inode_id);

        }
    }
}

uint32_t tee_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    char *data = (char *)calloc(MAX_BLOCK_POINT*2*DEVICE_BLOCK_SIZE-1, sizeof(char));
    char *buf = (char *)calloc(256, sizeof(char));
    uint32_t buf_len;
    uint32_t data_len;
    char *ptr = data;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        inode *dir_inode = (inode *)calloc(1, sizeof(inode));
        dir_inode = read_inode(dest_inode_id);
        dest_inode_id = search_in_dir(dir_inode, path_out[path_count - 1], TYPE_FILE);
        if (dest_inode_id != -1) {
            inode *file_inode = (inode *)calloc(1, sizeof(inode));
            file_inode = read_inode(dest_inode_id);
            fflush(stdin);
            fflush(stdout);
            while(fgets(buf, 255, stdin)!=NULL) {
                buf_len = strlen(buf);
                printf("%s\n", buf);
                strcpy(ptr, buf);
                ptr+=buf_len;
            }
            *(ptr+1) = '\0';
            sp_block *sp_ptr = read_superblock_data();
            write_file(sp_ptr, file_inode, data);
            edit_inode(file_inode, dest_inode_id);
            write_superblock_data(sp_ptr);
            free(sp_ptr);
        }
        // make_file(dest_inode_id, path_out[path_count - 1]);
    }
    free(path_out);
}


uint32_t cat(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        inode *dir_inode = (inode *)calloc(1, sizeof(inode));
        dir_inode = read_inode(dest_inode_id);
        dest_inode_id = search_in_dir(dir_inode, path_out[path_count - 1], TYPE_FILE);
        if (dest_inode_id != -1) {
            inode *file_inode = (inode *)calloc(1, sizeof(inode));
            file_inode = read_inode(dest_inode_id);
            fflush(stdin);
            fflush(stdout);
            char *data = read_file(file_inode);
            printf("%s\n", data);
            free(data);
        }
    }
    free(path_out);
}

char *cd(uint32_t *dir_inode_id, char *path_to, char *cur_path) {
    char **cur_path_out;
    char **path_out;

    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_to, path_out);

    cur_path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        cur_path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t cur_path_count = parse_path(cur_path, cur_path_out);
    
    char **temp_path;
    temp_path = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        temp_path[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t temp_path_count = 0;
    
    char *buf = (char *)calloc(DEVICE_BLOCK_SIZE, sizeof(char));
    uint32_t dest_inode_id;
    uint32_t cur_inode_no;
    char *ptr = buf;
    uint32_t buf_len = 0;
    uint32_t str_len;
    inode *cur_inode = (inode *)calloc(1, sizeof(inode));
    // if (*dir_inode_id == ROOT_DIR_INDEX || !strcmp(path_out[0], "/")) {
    if (!strcmp(path_out[0], "/")) {
        //当前目录为根目录，或cd目录为绝对目录：重建路径
        cur_inode_no = ROOT_DIR_INDEX;
        strcpy(ptr, "/");
        ptr++;
        if (path_count == 1) {
            //只有根目录：不用寻路，直接返回根目录
            *dir_inode_id = ROOT_DIR_INDEX;
            *ptr = '\0';
            free(cur_path_out);
            free(path_out);
            return buf;
        }
        strcpy(temp_path[0], "/");
        temp_path_count++;
        for (int i = 1; i < path_count; i++) {
            //需要寻路的情况：
            //若为普通目录，则找目录，找到则保存inode号，temp添加当前目录名,temp_path_count++
            //若为.，则无动作
            //若为..，则判断是否为根目录，若为根目录则无动作，否则找目录，保存inode号，temp当前设为/0，temp_path_count--
            cur_inode = read_inode(cur_inode_no);
            if (!strcmp(path_out[i], ".")) {
                continue;
            } else if (!strcmp(path_out[i], "..")) {
                if (cur_inode_no == ROOT_DIR_INDEX) {
                    continue;
                } else {
                    cur_inode_no = search_in_dir(cur_inode, "..", TYPE_DIR);
                    temp_path_count--;
                }
            } else {
                cur_inode_no = search_in_dir(cur_inode, path_out[i], TYPE_DIR);
                if (cur_inode_no == -1) {
                    printf("Path not exist!\n");
                    return cur_path;
                }
                strcpy(temp_path[temp_path_count], path_out[i]);
                temp_path_count++;
            }
        }
        if (temp_path_count == 1) {
            *dir_inode_id = ROOT_DIR_INDEX;
            *ptr = '\0';
            free(cur_path_out);
            free(path_out);
            return buf;
        }
        for (int i = 1; i < temp_path_count; i++) {
            //复制新路径到buf，返回
            str_len = strlen(temp_path[i]);
            strcpy(ptr, temp_path[i]);
            ptr[str_len] = '/';
            ptr += str_len;
            ptr++;
        }
        *(ptr-1) = '\0';
        free(cur_path_out);
        free(path_out);
        *dir_inode_id = cur_inode_no;
        return buf;    

    } else {
        //修改路径
        for (int i = 0; i < cur_path_count; i++) {
            strcpy(temp_path[i], cur_path_out[i]);
        }
        temp_path_count = cur_path_count;
        cur_inode_no = *dir_inode_id;
        for (int i = 0; i < path_count; i++) {
            cur_inode = read_inode(cur_inode_no);
            if (!strcmp(path_out[i], ".")) {
                continue;
            } else if (!strcmp(path_out[i], "..")) {
                if (cur_inode_no == ROOT_DIR_INDEX) {
                    continue;
                } else {
                    cur_inode_no = search_in_dir(cur_inode, "..", TYPE_DIR);
                    temp_path_count--;
                }
            } else {
                cur_inode_no = search_in_dir(cur_inode, path_out[i], TYPE_DIR);
                if (cur_inode_no == -1) {
                    printf("Path not exist!\n");
                    return cur_path;
                }
                strcpy(temp_path[temp_path_count], path_out[i]);
                temp_path_count++;
            }
        }
        ptr = buf + 1;
        if (temp_path_count == 1) {
            *dir_inode_id = ROOT_DIR_INDEX;
            buf[0] = '/';
            *ptr = '\0';
            free(cur_path_out);
            free(path_out);
            return buf;
        }
        buf[0] = '/';
        for (int i = 1; i < temp_path_count; i++) {
            //复制新路径到buf，返回
            str_len = strlen(temp_path[i]);
            strcpy(ptr, temp_path[i]);
            ptr[str_len] = '/';
            ptr += str_len;
            ptr++;
        }
        *(ptr-1) = '\0';
        free(cur_path_out);
        free(path_out);
        *dir_inode_id = cur_inode_no;
        return buf; 
    }
    // dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count, TYPE_DIR);
    //返回路径？需要知道当前路径(字符串)，若cd相对路径则改写路径，若cd绝对路径则重写路径？
    //需要注意到. .. /三种特殊字符

}

uint32_t rm_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    uint32_t del_file_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        inode *dir_inode = (inode *)calloc(1, sizeof(inode));
        dir_inode = read_inode(dest_inode_id);
        del_file_inode_id = search_in_dir(dir_inode, path_out[path_count - 1], TYPE_FILE);
        if (del_file_inode_id != -1) {
            inode *file_inode = (inode *)calloc(1, sizeof(inode));
            file_inode = read_inode(del_file_inode_id);
            //删除步骤：
            //1. 查看inode的link是否为1
            if (file_inode->link != 1) {
                //不为1的情况：硬链接
                //2. link--
                file_inode->link--;
                //3. 目录项修改:删除项，修改inode
                char *dir_data = read_file(dir_inode);
                char *write_ptr = dir_data;
                dir_item *dir_ptr = (dir_item *)calloc(1, sizeof(dir_item));
                uint32_t dir_count = dir_inode->size / DIR_ITEM_SIZE;
                for (int i = 0; i < dir_count; i++) {
                    memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*i), DIR_ITEM_SIZE);
                    if (!strcmp(dir_ptr->name, path_out[path_count-1]) && dir_ptr->type == TYPE_FILE) {
                        //发现需要删除的目录项
                        if (i == dir_count - 1) {
                            break;
                        } else {
                            for (int j = i + 1; j < dir_count; j++) {
                                memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*j), DIR_ITEM_SIZE);
                                memcpy(dir_data+(DIR_ITEM_SIZE*i), dir_ptr, DIR_ITEM_SIZE);
                                i++;
                            }
                            break;
                        }
                    }
                }
                dir_inode->size -= DIR_ITEM_SIZE;
                sp_block *sp_ptr = read_superblock_data();
                write_file(sp_ptr, dir_inode, dir_data);
                edit_inode(dir_inode, dest_inode_id);
                edit_inode(file_inode, del_file_inode_id);
                write_superblock_data(sp_ptr);
                free(sp_ptr);
                free(dir_data);
                return 0;
            } else {
                //为1的情况：删除文件
                //2. 释放文件块
                sp_block *sp_ptr = read_superblock_data();
                for (int i = 0; i < MAX_BLOCK_POINT; i++) {
                    if (file_inode->block_point[i] != -1) {
                        free_block(sp_ptr, file_inode->block_point[i]);
                    } else {
                        break;
                    }
                }
                //3. 删除inode
                remove_inode(sp_ptr, del_file_inode_id);
                //4. 目录项修改、目录inode修改
                char *dir_data = read_file(dir_inode);
                char *write_ptr = dir_data;
                dir_item *dir_ptr = (dir_item *)calloc(1, sizeof(dir_item));
                uint32_t dir_count = dir_inode->size / DIR_ITEM_SIZE;
                for (int i = 0; i < dir_count; i++) {
                    memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*i), DIR_ITEM_SIZE);
                    if (!strcmp(dir_ptr->name, path_out[path_count-1]) && dir_ptr->type == TYPE_FILE) {
                        //发现需要删除的目录项
                        if (i == dir_count - 1) {
                            break;
                        } else {
                            for (int j = i + 1; j < dir_count; j++) {
                                memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*j), DIR_ITEM_SIZE);
                                memcpy(dir_data+(DIR_ITEM_SIZE*i), dir_ptr, DIR_ITEM_SIZE);
                                i++;
                            }
                            break;
                        }
                    }
                }
                dir_inode->size -= DIR_ITEM_SIZE;
                //5. 写超级块etc
                // printf("%2x%2x\n", dir_data[6], dir_data[7]);
                write_file(sp_ptr, dir_inode, dir_data);
                edit_inode(dir_inode, dest_inode_id);
                write_superblock_data(sp_ptr);
                free(sp_ptr);
                free(dir_data);
                return 0;
            }
        }
    }
    free(path_out);
}

uint32_t rmdir_single_arg(uint32_t cur_dir_inode_id, char *path_in) {
    char **path_out;
    path_out = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count = parse_path(path_in, path_out);
    uint32_t dest_inode_id;
    uint32_t del_dir_inode_id;
    if (path_count == 1) {
        dest_inode_id = cur_dir_inode_id;
    } else {
        dest_inode_id = find_inode_by_path(cur_dir_inode_id, path_out, path_count - 1, TYPE_DIR);
    }
    if (dest_inode_id != -1) {
        inode *dir_inode = (inode *)calloc(1, sizeof(inode));
        dir_inode = read_inode(dest_inode_id);
        del_dir_inode_id = search_in_dir(dir_inode, path_out[path_count - 1], TYPE_DIR);
        if (del_dir_inode_id != -1) {
            inode *deldir_inode = (inode *)calloc(1, sizeof(inode));
            deldir_inode = read_inode(del_dir_inode_id);
            //删除步骤：
            //1. 查看inode的link是否为1
            if (deldir_inode->size != 2*DIR_ITEM_SIZE) {
                //非空目录
                printf("Cannot delete a nonempty directory!\n");
                return -1;
            } else if (del_dir_inode_id == ROOT_DIR_INDEX) {
                printf("Cannot delete root directory!\n");
                return -1;
            } else if (del_dir_inode_id == cur_dir_inode_id) {
                printf("Cannot delete current directory!\n");
                return -1;
            } else {
                //为1的情况：删除文件
                //2. 释放文件块
                sp_block *sp_ptr = read_superblock_data();
                for (int i = 0; i < MAX_BLOCK_POINT; i++) {
                    if (deldir_inode->block_point[i] != -1) {
                        free_block(sp_ptr, deldir_inode->block_point[i]);
                    } else {
                        break;
                    }
                }
                //3. 删除inode
                remove_inode(sp_ptr, del_dir_inode_id);
                //4. 目录项修改、目录inode修改
                char *dir_data = read_file(dir_inode);
                char *write_ptr = dir_data;
                dir_item *dir_ptr = (dir_item *)calloc(1, sizeof(dir_item));
                uint32_t dir_count = dir_inode->size / DIR_ITEM_SIZE;
                for (int i = 0; i < dir_count; i++) {
                    memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*i), DIR_ITEM_SIZE);
                    if (!strcmp(dir_ptr->name, path_out[path_count-1]) && dir_ptr->type == TYPE_DIR) {
                        //发现需要删除的目录项
                        if (i == dir_count - 1) {
                            break;
                        } else {
                            for (int j = i + 1; j < dir_count; j++) {
                                memcpy(dir_ptr, dir_data+(DIR_ITEM_SIZE*j), DIR_ITEM_SIZE);
                                memcpy(dir_data+(DIR_ITEM_SIZE*i), dir_ptr, DIR_ITEM_SIZE);
                                i++;
                            }
                            break;
                        }
                    }
                }
                dir_inode->size -= DIR_ITEM_SIZE;
                //5. 写超级块etc
                // printf("%2x%2x\n", dir_data[6], dir_data[7]);
                write_file(sp_ptr, dir_inode, dir_data);
                edit_inode(dir_inode, dest_inode_id);
                write_superblock_data(sp_ptr);
                free(sp_ptr);
                free(dir_data);
                return 0;
            }
        }
    }
    free(path_out);
}


uint32_t mv(uint32_t cur_dir_inode_id, char *path_src, char *path_dest) {
    cp(cur_dir_inode_id, path_src, path_dest);
    rm_single_arg(cur_dir_inode_id, path_src);
}

uint32_t ln(uint32_t cur_dir_inode_id, char *path_src, char *path_dest) {
    char **path_out_src;
    path_out_src = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out_src[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count_src = parse_path(path_src, path_out_src);
    char **path_out_dest;
    path_out_dest = (char **)calloc(32, sizeof(char *));
    for (int i = 0; i < 32; i++) {
        path_out_dest[i] = (char *)calloc(32, sizeof(char));
    }
    uint32_t path_count_dest = parse_path(path_dest, path_out_dest);
    uint32_t src_inode_id = find_inode_by_path(cur_dir_inode_id, path_out_src, path_count_src, TYPE_FILE);
    if (src_inode_id != -1) {
        uint32_t dest_dir_inode_id;
        if (path_count_dest == 1) {
            dest_dir_inode_id = cur_dir_inode_id;
        } else {
            dest_dir_inode_id = find_inode_by_path(cur_dir_inode_id, path_out_dest, path_count_dest-1, TYPE_DIR);
        }
        if (dest_dir_inode_id != -1) {
            // move_file(path_out_dest[path_count_dest-1], src_inode_id, dest_dir_inode_id);
            inode *dest_dir = read_inode(dest_dir_inode_id);
            if (dest_dir->file_type != TYPE_DIR) {
                printf("invalid inode!\n");
                return -1;
            }
            sp_block *sp_ptr = read_superblock_data();
            if (search_in_dir(dest_dir, path_out_dest[path_count_dest-1], TYPE_FILE) != -1) {
                printf("file already exist!\n");
                return -1;
            }
            if (!strcmp(path_out_dest[path_count_dest-1], "/")) {
                printf("invalid name!\n");
                return -1;
            }
            int block = 6;
            int dir_item_count = dest_dir->size / DIR_ITEM_SIZE;
            for (int i = 0; i < MAX_BLOCK_POINT; i++) {
                if (dest_dir->block_point[i] == -1) {
                    block = i;
                    break;
                } 
            }
            if (block == MAX_BLOCK_POINT && dir_item_count == MAX_BLOCK_POINT * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
                printf("dir item full!\n");
                return -1;
            } else if (dir_item_count == block * (2 * DEVICE_BLOCK_SIZE) / DIR_ITEM_SIZE) {
                printf("need to allocate new block for new dir item\n");
                if (sp_ptr->free_block_count < 1) {
                    printf("no enough free block!\n");
                    return -1;
                }
                uint32_t dest_dir_new_blockno = allocate_new_block(sp_ptr);
                if (dest_dir_new_blockno == -1) {
                    printf("allocate new block failed!\n");
                    return -1;
                }
                dest_dir->block_point[block] = dest_dir_new_blockno;
                dest_dir->size += DIR_ITEM_SIZE;
                edit_inode(dest_dir, cur_dir_inode_id);
                inode *src_file_inode = read_inode(src_inode_id);
                src_file_inode->link++;
                edit_inode(src_file_inode, src_inode_id);
                dir_item new_file;
                new_file.inode_id = src_inode_id;
                new_file.valid = VALID;
                new_file.type = TYPE_FILE;
                memcpy(new_file.name, path_out_dest[path_count_dest-1], sizeof(new_file.name));
                char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
                memcpy(buf, &new_file, sizeof(dir_item));
                if (write_fileblock(buf, dest_dir_new_blockno) == -1) {
                    printf("write fileblock failed!\n");
                    return -1;
                }
                free(buf);
                write_superblock_data(sp_ptr);
                return 0;
            } else {
                inode *src_file_inode = read_inode(src_inode_id);
                src_file_inode->link++;
                uint32_t ptr = dest_dir->size - (block - 1) * 2 * DEVICE_BLOCK_SIZE;
                dest_dir->size += DIR_ITEM_SIZE;
                edit_inode(dest_dir, dest_dir_inode_id);
                edit_inode(src_file_inode, src_inode_id);
                dir_item new_file;
                new_file.inode_id = src_inode_id;
                new_file.valid = VALID;
                new_file.type = TYPE_FILE;
                memcpy(new_file.name, path_out_dest[path_count_dest-1], sizeof(new_file.name));
                char *buf = (char *)calloc(2 * DEVICE_BLOCK_SIZE, sizeof(char));
                buf = read_fileblock(dest_dir->block_point[block-1]);
                memcpy(buf+ptr, &new_file, sizeof(dir_item));
                if (write_fileblock(buf, dest_dir->block_point[block-1]) == -1) {
                    printf("write fileblock failed!\n");
                    return -1;
                }
                free(buf);
                write_superblock_data(sp_ptr);
                return 0;
            }
        }
    }
}

int main() {
    printf("Opening file system\n");
    int i = open_disk();
    // printf("Open disk result: %d\n", i);
    sp_block *sp_ptr = read_superblock_data();
    char temp[128];
    if (sp_ptr == NULL || sp_ptr->magic_num != 0x97ec6587) {
        printf("Magic number invalid! Would you like to format the disk? (Y/N): ");
        fgets(temp, 3, stdin);
        if (temp[1] == '\n')
            temp[1] = '\0';
        if (!strcmp(temp, "Y")) {
            close_disk();
            create_disk();
            i = open_disk();
            init_superblock();
            init_root_dir();
            sp_ptr = read_superblock_data();
        } else {
            printf("Exit shell\n");
            return 0;
        }
    } else {
        printf("Naive EXT2 File System found! Would you like to format the disk? (Y/N): ");
        fgets(temp, 3, stdin);
        if (temp[1] == '\n')
            temp[1] = '\0';
        if (!strcmp(temp, "Y")) {
            close_disk();
            create_disk();
            i = open_disk();
            init_superblock();
            init_root_dir();
            sp_ptr = read_superblock_data();
        } 
    }

    printf("free_block_count: %d\n", sp_ptr->free_block_count);

    char buf[1024];
    char *path = (char *)calloc(2*DEVICE_BLOCK_SIZE, sizeof(char));
    char *input_path = (char *)calloc(2*DEVICE_BLOCK_SIZE, sizeof(char));
    strcpy(path, "/");
    memset(buf, '\0', sizeof(buf));
    char **path_out;
    uint32_t current_dir_inode_id = ROOT_DIR_INDEX;

    while(1) {
        fflush(stdin);
        fflush(stdout);
        printf("Naive EXT2:%s$ ", path);
        fflush(stdin);
        fflush(stdout);
        fgets(buf, 1000, stdin);
        uint32_t len = strlen(buf);
        if (buf[len-1] == '\n') {
            buf[len-1] = '\0';
            len--;
        }
        
        path_out = (char **)calloc(32, sizeof(char *));
        for (int i = 0; i < 32; i++) {
            path_out[i] = (char *)calloc(128, sizeof(char));
        }
        uint32_t path_count = parse_args(buf, path_out);
        // printf("count: %d\n", path_count);
        if (path_count == 0) {
            // printf("\n");
        } else {
            if (!strcmp(path_out[0], "ls")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count == 1) {
                    ls_single_arg(current_dir_inode_id, ".");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        ls_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "mkdir")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count == 1) {
                    printf("Usage: mkdir path1 [path2..]\n");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        mkdir_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "touch")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count == 1) {
                    printf("Usage: touch file1 [file2..]\n");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        touch_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "cp")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count != 3) {
                    printf("Usage: cp src_file dest_file\n");
                } else {
                    cp(current_dir_inode_id, path_out[1], path_out[2]);
                }
            } else if (!strcmp(path_out[0], "tee")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count == 1) {
                    printf("Usage: tee file1 [file2..]\n");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        tee_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "cat")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count != 2) {
                    printf("Usage: cat file\n");
                } else {
                    cat(current_dir_inode_id, path_out[1]);
                }
            } else if (!strcmp(path_out[0], "cd")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count != 2) {
                    printf("Usage: cd path\n");
                } else {
                    strcpy(input_path, path);
                    path = cd(&current_dir_inode_id, path_out[1], input_path);
                    // current_dir_inode_id = cd(current_dir_inode_id, path_out[1]);
                    // printf("%d\n", current_dir_inode_id);
                }
            } else if (!strcmp(path_out[0], "rm")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count < 2) {
                    printf("Usage: rm file1 [file2..]\n");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        rm_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "rmdir")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count < 2) {
                    printf("Usage: rmdir dir1 [dir2..]\n");
                } else {
                    for (int i = 0; i < path_count - 1; i++) {
                        rmdir_single_arg(current_dir_inode_id, path_out[i+1]);
                    }
                }
            } else if (!strcmp(path_out[0], "mv")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count != 3) {
                    printf("Usage: mv src_file dest_file\n");
                } else {
                    mv(current_dir_inode_id, path_out[1], path_out[2]);
                }
            } else if (!strcmp(path_out[0], "ln")) {
                // printf("command: %s\n", path_out[0]);
                if (path_count != 3) {
                    printf("Usage: ln src_file dest_file\n");
                } else {
                    ln(current_dir_inode_id, path_out[1], path_out[2]);
                }
            } else if (!strcmp(path_out[0], "spblock")) {
                // printf("command: %s\n", path_out[0]);
                sp_block *sp_ptr = read_superblock_data();
                printf("Superblock data:\n");
                printf("Free block count: %d\n", sp_ptr->free_block_count);
                printf("Free inode count: %d\n", sp_ptr->free_inode_count);
                printf("Dir inode count: %d\n", sp_ptr->dir_inode_count);
                printf("Fileblock 32-63 allocation: %u\n", sp_ptr->block_map[1]);
            } else if (!strcmp(path_out[0], "shutdown")) {
                // printf("command: %s\n", path_out[0]);
                printf("Will exit Naive EXT2 File System! Would you like to format the disk? (Y/N): ");
                fgets(temp, 3, stdin);
                if (temp[1] == '\n')
                    temp[1] = '\0';
                if (!strcmp(temp, "Y")) {
                    create_disk();
                }
                close_disk();
                printf("Goodbye! \n");
                break;
            } else {
                printf("unknown command\n");
            }
        }
        free(path_out);
    }
    
    return 0;
}