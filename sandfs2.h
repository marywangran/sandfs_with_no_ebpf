#ifndef _LINUX_SANDFS_H
#define _LINUX_SANDFS_H

/*  Avoid :
 *  warning: the frame size of MAX_NUM_ARGS*size_of_args bytes is larger than 1024 bytes 
 */
#define MAX_NUM_ARGS 50

typedef enum {
	SANDFS_LOOKUP,
	SANDFS_OPEN,
	SANDFS_CLOSE,
	SANDFS_READ,
	SANDFS_WRITE,
	SANDFS_HOOK_MAX,
} sandfs_op_t;

typedef enum {
	SANDFS_IDX_CRED,
	SANDFS_IDX_PATH,
	SANDFS_IDX_POS,
	SANDFS_IDX_COUNT,
	SANDFS_IDX_BUF,
} sandfs_args_index_t;

typedef enum {
	OPCODE = 0,
	NUM_ARGS,
	PARAM_0_SIZE,
	PARAM_0_VALUE,
	PARAM_1_SIZE,
	PARAM_1_VALUE,
	PARAM_2_SIZE,
	PARAM_2_VALUE,
	PARAM_3_SIZE,
	PARAM_3_VALUE,
} sandfs_arg_t;

struct sandfs_arg {
	uint32_t size;
	void *value;
};

struct sandfs_args {
	sandfs_arg_t op;
	uint32_t num_args;
	struct sandfs_arg args[MAX_NUM_ARGS];
};

#define DESC_MAX	32
struct vfs_rule {
	struct list_head list;
	char name[DESC_MAX];
	int (*func)(unsigned int, struct sandfs_args *, void *, int *);
	unsigned int hooknum;
	void *priv;
};

#endif /* _LINUX_SANDFS_H */
