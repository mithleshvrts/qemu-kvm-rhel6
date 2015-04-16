/*
 * $Id$
 * $Copyright$
 */
#ifndef OFLAMED_H
#define OFLAMED_H

#include <gmodule.h>
#include <inttypes.h>
#include <pthread.h>

#include "qemu-common.h"
#include "qemu-error.h"
#include "block_int.h"
#include "uri.h"
#include "qemu-lock.h"

#ifndef OFLAME_DEBUG
#define oflameErr(...) {\
	time_t t = time(0); \
	char buf[9] = {0}; \
	strftime(buf, 9, "%H:%M:%S", localtime(&t)); \
	fprintf(stderr, "[%s: %lu] %d: %s():\t", buf, pthread_self(), __LINE__, __FUNCTION__);\
	fprintf(stderr, __VA_ARGS__);\
}
#define oflameDbg oflameErr
#else
#define oflameErr(...)	{/**/}
#endif

typedef enum {
    VDISK_AIO_READ,
    VDISK_AIO_WRITE,
    VDISK_STAT,
    VDISK_TRUNC,
    VDISK_AIO_FLUSH,
    VDISK_AIO_RECLAIM,
    VDISK_AIO_LAST_CMD
} VDISKAIOCmd;

typedef enum {
    OFLAME_IO_INPROGRESS,
    OFLAME_IO_COMPLETED,
    OFLAME_IO_ERROR
} OFLAMEIOTypes;
	
#define VDISK_FD_READ 0
#define VDISK_FD_WRITE 1

typedef void *qemu_aio_ctx_t; 
typedef void (*ird_callback_t)(ssize_t retval, void *arg);

#define IRD_VDISK_NONE		0x00
#define IRD_VDISK_CREATE	0x01

#define QEMUIRD_MAX_IO_SIZE	4194304		/* This is max IO in QEMUIRD lib */

/*
 * Opcodes for making IOCTL on QEMUIRD library
 */
#define BASE_OPCODE_SHARED		1000	
#define BASE_OPCODE_DAL			2000
#define IRP_VDISK_STAT                  (BASE_OPCODE_SHARED + 5)
#define IRP_VDISK_GET_GEOMETRY          (BASE_OPCODE_DAL + 17)
#define IRP_VDISK_READ_PARTITION        (BASE_OPCODE_DAL + 18)
#define IRP_VDISK_FLUSH                 (BASE_OPCODE_DAL + 19)


char vdisk_prefix[] = "/dev/of/vdisk";
#define OF_MAX_FILE_LEN		1024
#define OF_MAX_SERVER_ADDR		1024

typedef struct qemu2ird_ctx {
    uint32_t		ird_flag;
    uint64_t		ird_size;
    char		*ird_channel;
    char 		*target;
    ird_callback_t	ird_cb;
} qemu2ird_ctx_t;

typedef qemu2ird_ctx_t ird2qemu_ctx_t;

typedef struct LibIrdSymbol {
        const char *name;
        gpointer *addr;
} LibIrdSymbol;

typedef void (*iio_cb_t) (uint32_t rfd, uint32_t reason, void *ctx, void *reply);
typedef struct IridiumOps {
	void * (* qemu_iio_init)(iio_cb_t cb);
	int32_t (* qemu_open_iio_conn)(void *ird_ctx, const char *uri, uint32_t flags);
	int32_t (* qemu_iio_devopen)(void *ird_ctx, uint32_t cfd, const char *devpath, uint32_t flags);
	int32_t (* qemu_iio_devclose)(void *ird_ctx, uint32_t rfd);
	int32_t (* qemu_iio_writev)(void *ird_ctx, uint32_t rfd, struct iovec *iov, int iovcnt, uint64_t offset, void *ctx, uint32_t flags);
	int32_t (* qemu_iio_readv)(void *ird_ctx, uint32_t rfd, struct iovec *iov, int iovcnt, uint64_t offset, void *ctx, uint32_t flags);
	int32_t (* qemu_iio_read)(void *ird_ctx, uint32_t rfd, unsigned char *buf, uint64_t size, uint64_t offset, void *ctx, uint32_t flags);
	int32_t (* qemu_iio_ioctl)(void *apictx, uint32_t rfd, uint32_t opcode, void *in, void *ctx, uint32_t flags);
	int32_t (* qemu_iio_close)(void *ird_ctx, uint32_t cfd);
	uint32_t (* qemu_iio_extract_msg_error)(void *ptr);
} IridiumOps;

//void (qeumu_iio_cb_t) (uint32_t rfd, uint32_t reason, void *ctx, io_ird_msg *reply);
int32_t qemu_open_iridium_conn(const char *uri, uint32_t lanes, uint32_t flags);
int32_t qemu_iio_devopen(void *ird_ctx, uint32_t cfd, const char *devpath, uint32_t flags);
int32_t qemu_iio_writev(void *ird_ctx, uint32_t rfd, void *ctx, uint64_t offset, uint32_t count, struct iovec *iov, uint32_t flags);
int32_t qemu_iio_readv(void *ird_ctx, uint32_t rfd, void *ctx, uint64_t offset, uint32_t count, struct iovec *iov, uint32_t flags);


typedef struct iio_msg_t
{
   enum
   {
       IIOM_DTYPE_NONE,   /* No data is present */
       IIOM_DTYPE_PS,     /* The type of the data is a propertyset */
       IIOM_DTYPE_BYTES    /* The type of the data is a counted_byte */
   } type;
   uint32_t iio_error;          /* Error code */
   union
   {
       struct
       {
           unsigned char  *iio_recv_buf;  /* The data pointer, this is allocated by the caller */
           uint64_t iio_len; /* The size of buffer as provided in the request */
           uint64_t iio_nbytes; /* The number of bytes written or read */
       } iio_buf;
       void *iio_ps;    /* Propertyset */
       uint32_t iio_etype; /* A number indicating the event */
   } iio_data;
}iio_msg;


/*
 * OpenFlame AIO callbacks structure
 */

typedef struct OFlameAIOCB {
    BlockDriverAIOCB 	common;
    size_t 		ret;
    int 		aio_done;
    size_t 		size;
    QEMUBH 		*bh;
    int			segments;
    spinlock_t		seg_lock;	/* This just protects the the Segments field of ACB */ 
    size_t		last_offset;
} OFlameAIOCB;


/*
 * Structure per vDisk maintained for state
 */

typedef struct BDRVOFlameState {
    int 		fds[2];
    int64_t		vdisk_size;
    int64_t		vdisk_blocks;
    int 		vdisk_aio_count;
    int 		reader_pos;
    OFlameAIOCB 	*ird_event_acb;
    int 		rfd;
    int			ird_cfd;
    void		*ird_ctx;
    URI			*uri;
} BDRVOFlameState;

static IridiumOps irdops;
static GModule *lib_qemuird_handle;
int32_t	qemu_ird_cfd;
void *global_ird_ctx = NULL;
spinlock_t of_global_ctx_lock = SPIN_LOCK_UNLOCKED;


void oflame_complete_aio(OFlameAIOCB *acb, BDRVOFlameState *s);
void oflame_iio_callback(uint32_t rfd, uint32_t reason, void *ctx, void *m);
int oflame_load_iio_ops(void);
void oflame_finish_aiocb(ssize_t ret, void *arg);
int qemu_ird_init(BDRVOFlameState *s, const char *oflame_uri);
BlockDriverAIOCB *oflame_aio_flush(BlockDriverState *bs,
		BlockDriverCompletionFunc *cb, void *opaque);
BlockDriverAIOCB* oflame_aio_discard(BlockDriverState *bs, int64_t sector_num,
                                            int nb_sectors, BlockDriverCompletionFunc *cb,
                                            void *opaque);
int qemu_ird_fini(BDRVOFlameState *s);
unsigned long oflame_get_vdisk_stat(BDRVOFlameState *s);
void oflame_aio_event_reader(void *opaque);

int qemu_submit_io(BDRVOFlameState *s, struct iovec *iov, int64_t niov,
			  int64_t offset, int cmd, qemu_aio_ctx_t acb);
void bdrv_oflame_init(void);
int oflame_aio_flush_cb(void *opaque);

void * oflame_initialize(void);
void * oflame_setup_ird(void);
int oflame_open(BlockDriverState *bs, const char *oflame_uri,
		int bdrv_flags);
void oflame_aio_cancel(BlockDriverAIOCB *blockacb);
int oflame_truncate(BlockDriverState *bs, int64_t offset);
BlockDriverAIOCB *oflame_aio_readv(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque);
BlockDriverAIOCB *oflame_aio_writev(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque);
coroutine_fn int oflame_co_read(BlockDriverState *bs, int64_t sector_num,
                                    uint8_t *buf, int nb_sectors);
coroutine_fn int oflame_co_write(BlockDriverState *bs, int64_t sector_num,
                                     const uint8_t *buf, int nb_sectors);
int64_t oflame_get_allocated_blocks(BlockDriverState *bs);
void oflame_close(BlockDriverState *bs);
BlockDriverAIOCB *oflame_aio_rw(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque, int write);
int64_t oflame_getlength(BlockDriverState *bs);
void oflame_inc_acb_segments(void *ptr, uint32_t delta, size_t offset);
void oflame_dec_acb_segments(void *ptr, uint32_t delta);
inline int oflame_dec_n_get_acb_segments(void *ptr, uint32_t delta);
#endif // OFLAMED_H
