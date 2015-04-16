/*
 * $Id$
 * $Copyright$
 */
/*
 * QEMU Block driver for vDisk (Symantec OpenFlame)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "oflame.h"
/*
 * Loading IRIDIUM operation from qemuird library at run time.
 * It loads only when first oflame_open called for a vDisk
 */

inline void oflame_inc_acb_segments(void *ptr, uint32_t delta, size_t offset)
{
	assert (ptr != NULL);
	OFlameAIOCB *acb = (OFlameAIOCB *)ptr;

	spin_lock(&(acb->seg_lock));
	acb->segments += delta; 
	acb->last_offset = offset; 
	spin_unlock(&(acb->seg_lock));
}

inline void oflame_dec_acb_segments(void *ptr, uint32_t delta)
{
	assert (ptr != NULL);
	OFlameAIOCB *acb = (OFlameAIOCB *)ptr;

	spin_lock(&(acb->seg_lock));
	acb->segments -= delta; 
	spin_unlock(&(acb->seg_lock));
}

inline int oflame_dec_n_get_acb_segments(void *ptr, uint32_t delta)
{
	int seg = 0;
	assert (ptr != NULL);
	OFlameAIOCB *acb = (OFlameAIOCB *)ptr;

	spin_lock(&(acb->seg_lock));
	acb->segments -= delta; 
	seg = acb->segments;
	spin_unlock(&(acb->seg_lock));
	return seg;
}

void oflame_iio_callback(uint32_t rfd, uint32_t reason, void *ctx, void *m)
{
	OFlameAIOCB *acb = (OFlameAIOCB *) ctx;
	BlockDriverState *bs = acb->common.bs;
	BDRVOFlameState *s = bs->opaque;
	int rv;
	int seg = 0;
	uint32_t err =  (*irdops.qemu_iio_extract_msg_error)(m);

//	oflameDbg("We we got called for  acb =%p, acb->segments = %d. reason = %x return error code = %u last_offset = %lu\n", acb, acb->segments, reason, err, acb->last_offset);
	if (reason == 0x0004) {		/* IIO_REASON_DONE == 0x0004	*/
		oflameDbg("INFO : We got called for reason = %d , acb = %p, acb->segments = %d, acb->size = %lu Error = %d\n", reason, acb, acb->segments, acb->size, err);
		acb->ret += err;
	} else {
		oflameDbg("ALERT : We got called for reason = %d , acb = %p, acb->segments = %d, acb->size = %lu Error = %d\n", reason, acb, acb->segments, acb->size, err);
	}	
	acb->ret += err;
	seg = oflame_dec_n_get_acb_segments(acb, 1);
	if (seg != 0) {
		oflameDbg("We have more segments of acb =%p, acb->segments = %d\n", acb, seg);
	} else {
		rv = qemu_write_full(s->fds[VDISK_FD_WRITE], &acb, sizeof(acb));
		if (rv != sizeof(acb)) {
			error_report("OFlame AIO completion failed: %s", strerror(errno));
			abort();
		}
	}
}

int oflame_load_iio_ops(void)
{
	int i = 0;
	LibIrdSymbol ird_symbols[] = {
		{"qemu_iio_init",
			(gpointer *) &irdops.qemu_iio_init},
		{"qemu_open_iio_conn",
			(gpointer *) &irdops.qemu_open_iio_conn},
		{"qemu_iio_devopen",
			(gpointer *) &irdops.qemu_iio_devopen},
		{"qemu_iio_devclose",
			(gpointer *) &irdops.qemu_iio_devclose},
		{"qemu_iio_writev",
			(gpointer *) &irdops.qemu_iio_writev},
		{"qemu_iio_readv",
			(gpointer *) &irdops.qemu_iio_readv},
		{"qemu_iio_read",
			(gpointer *) &irdops.qemu_iio_read},
		{"qemu_iio_ioctl",
			(gpointer *) &irdops.qemu_iio_ioctl},
		{"qemu_iio_close",
			(gpointer *) &irdops.qemu_iio_close},
		{"qemu_iio_extract_msg_error",
			(gpointer *) &irdops.qemu_iio_extract_msg_error},

		{NULL}
	};


	if (!g_module_supported()) {
		error_report("modules are not supported on this platform: %s",
				g_module_error());
		return -EIO;
	}

	lib_qemuird_handle = g_module_open("/opt/SYMCofcore/lib/libqemuird.so.1", 0);
	if (!lib_qemuird_handle) {
		error_report("error loading irdops: %s", g_module_error());
		return -EIO;
	}

	g_module_make_resident(lib_qemuird_handle);

	while (ird_symbols[i].name) {
		const char *name = ird_symbols[i].name;
		if (!g_module_symbol(lib_qemuird_handle, name, ird_symbols[i].addr)) {
			error_report("%s could not be loaded from irdops : %s",
					name, g_module_error());
			return -EIO;
		}
		++i;
	}

	oflameDbg("iridium ops loaded\n");
	
	return 0;
}


void oflame_complete_aio(OFlameAIOCB *acb, BDRVOFlameState *s)
{
	int ret;
	BlockDriverCompletionFunc *cb = acb->common.cb;
	void *opaque = acb->common.opaque;

	if (acb->ret != 0)
	{
		ret = -EIO;
	}
	else
	{
	/*
	 * We mask all the IO errors generically as EIO for upper layers
	 * Right now our IO Manager uses non standard error codes. Instead
	 * of confusing upper layers with incorrect interpretation we are
	 * doing this workaround.
	 */ 	
		ret = 0;
	}

	s->vdisk_aio_count--;
//	oflameDbg("oflame_complete_aio : ACB = %p , acb->ret = %lu acb->size = %lu outstanding IO = %d..\n", acb, acb->ret, acb->size, s->vdisk_aio_count);
//	oflameDbg("releasing qemu aio. aio->ret =%d\n", acb->ret);
	acb->aio_done = OFLAME_IO_COMPLETED;
	qemu_aio_release(acb);
	cb(opaque, ret);
}

/*
 * This is the OpenFlame event handler registered to QEMU.
 * It invoked when any IO completed and written on pipe
 * by callback called from IRIDIUM thread context. Then it mark
 * the AIO as completed and release OpenFlame AIO callbacks.
 */

void oflame_aio_event_reader(void *opaque)
{
	BDRVOFlameState *s = opaque;
	ssize_t ret;

//	oflameDbg("Event for reading caught in QEMU\n");
	do {
		char *p = (char *)&s->ird_event_acb;

		ret = read(s->fds[VDISK_FD_READ], p + s->reader_pos,
				sizeof(s->ird_event_acb) - s->reader_pos);
		if (ret > 0) {
			s->reader_pos += ret;
			if (s->reader_pos == sizeof(s->ird_event_acb)) {
				s->reader_pos = 0;
				oflame_complete_aio(s->ird_event_acb, s);
			}
		}
	} while (ret < 0 && errno == EINTR);
}

/*
 * QEMU calls this to check if any pending IO on vDisk
 * It will wait in loop until all the AIO completed.
 */

int oflame_aio_flush_cb(void *opaque)
{
	BDRVOFlameState *s = opaque;

	return s->vdisk_aio_count;
}

/*
 * Calling IRD operation for READ/WRITE
 */

int qemu_submit_io(BDRVOFlameState *s, struct iovec *iov, int64_t niov,
			  int64_t offset, int cmd, qemu_aio_ctx_t acb)
{
	oflameDbg("calling qemu_ird_submit_io ops\n");
/*	return (*irdops.qemu_ird_submit_io)(iov, niov, offset, s->qemu2ird_ctx,

						cmd, acb);
*/
	return 0;
}

/*
 * This will be called by QEMU while booting for each vDisks.
 * bs->opaque will be allocated by QEMU upper block layer before calling open.
 * It will load all the IRIDIUM operations from qemuird library
 * and call IRD operation to create channel to doing IO on vDisk.
 * It parse the URI and get the hostname and vDisk path. Then
 * set OpenFlame event handler to QEMU.
 */

void * oflame_initialize(void)
{
	void *ird_ctx = NULL;
	if (oflame_load_iio_ops() < 0) {
		oflameDbg("Could not load the Iridium IO library. Aborting\n");
		return ird_ctx;
	}

	ird_ctx = (*irdops.qemu_iio_init)(oflame_iio_callback);

	return ird_ctx;
}

void * oflame_setup_ird(void)
{
	void *ird_ctx = NULL;
	ird_ctx = oflame_initialize();
	if (ird_ctx != NULL) {
		oflameDbg("The return of iio_init for 9960 -debug is : %d. On IO Manager.\n", qemu_ird_cfd);
	} else {
		oflameDbg("Could not initialize the channel. Bailing out\n");
	}
	return ird_ctx;
}
int oflame_open(BlockDriverState *bs, const char *oflame_uri,
		int bdrv_flags)
{
	BDRVOFlameState *s = bs->opaque;
	URI * uri;
	int ret = 0;
	char *file_name;
	char *of_vsa_addr;

	spin_lock(&of_global_ctx_lock);
	if (global_ird_ctx == NULL) {
		global_ird_ctx = oflame_setup_ird();
		if (global_ird_ctx == NULL) {
			oflameDbg("Error while opening the device. Bailing out\n");
		}
	}
	spin_unlock(&of_global_ctx_lock);

	of_vsa_addr = (char *) malloc (sizeof(char) * OF_MAX_SERVER_ADDR);
	if (!of_vsa_addr) {
		oflameDbg("Could not allocate memory for file parsing. Bailing out\n");
		return -ENOMEM;
	}
	file_name = (char *) malloc (sizeof(char) * OF_MAX_FILE_LEN);
	if (!file_name) {
		oflameDbg("Could not allocate memory for file parsing. Bailing out\n");
		free(of_vsa_addr);
		return -ENOMEM;
	}

	/*
 	 * Below steps need to done by all the block driver in QEMU which
 	 * support AIO. Need to create pipe for communicating b/w two threads
 	 * in different context. And set handler for read event when IO completion
 	 * done by non-QEMU context.
 	 */

	uri = uri_parse(oflame_uri);
	if (!uri) {
		oflameDbg("Could not parse the uri string. Aborting volume open\n");
		ret = -EIO;
		goto out;
	}
	s->uri = uri;	
	snprintf(file_name, OF_MAX_FILE_LEN, "%s%s", vdisk_prefix, uri->path);

	snprintf(of_vsa_addr, OF_MAX_SERVER_ADDR, "of://%s:%d", uri->server, uri->port );
	oflameDbg("Trying to connection to : %s\n", of_vsa_addr);
	qemu_ird_cfd = (*irdops.qemu_open_iio_conn)(global_ird_ctx, of_vsa_addr, 0);
	if (!qemu_ird_cfd) {
		oflameDbg("Could not open a connection to :  %s\n", of_vsa_addr);
		ret = -EIO;
		goto out;
	}
	oflameDbg("Trying to open the device : %s\n", file_name);
	s->ird_ctx = global_ird_ctx;
	s->ird_cfd = qemu_ird_cfd;
	s->vdisk_size = 0;
	s->rfd = (*irdops.qemu_iio_devopen)(s->ird_ctx, s->ird_cfd, file_name, 0);

	oflameDbg("s->ird_cfd = %d , s->rfd = %d \n", s->ird_cfd, s->rfd);
	ret = qemu_pipe(s->fds);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}
	fcntl(s->fds[VDISK_FD_READ], F_SETFL, O_NONBLOCK);
	oflameDbg("setting QEMU fd handler for openflame driver\n");
	qemu_aio_set_fd_handler(s->fds[VDISK_FD_READ],
			oflame_aio_event_reader, NULL, oflame_aio_flush_cb, NULL, s);

	free(file_name);
	return 0;

out:
	if (s->rfd != 0)
	{
		irdops.qemu_iio_devclose(s->ird_ctx, s->rfd);
	}

	if (s->ird_cfd != 0)
	{
		irdops.qemu_iio_close(s->ird_ctx, s->ird_cfd);
	}
	uri_free(uri);
	free(file_name);
	free(of_vsa_addr);
	return ret;
}

/*
 * This is called when some activity like remove disk initiated
 * from the guest, then it will try to cancel all the IO submitted
 * to vDisk
 */

void oflame_aio_cancel(BlockDriverAIOCB *blockacb)
{
	OFlameAIOCB *acb = (OFlameAIOCB *)blockacb;

	oflameDbg("cancelling aio\n");
	while (acb->aio_done == OFLAME_IO_INPROGRESS) {
		qemu_aio_wait();
	}
	qemu_aio_release(acb);
	oflameDbg("returning..\n");
}

static AIOPool oflame_aio_pool = {
	.aiocb_size = sizeof(OFlameAIOCB),
	.cancel = oflame_aio_cancel,
};

/*
 * This is called in IRIDIUM thread context when IO done
 * on IO Manager and IRIDIUM client received the data or
 * ACK. It notify another event handler thread running in QEMU context
 * by writing on the pipe
 */

void oflame_finish_aiocb(ssize_t ret, void *arg)
{
	OFlameAIOCB *acb = (OFlameAIOCB *) arg;
	BlockDriverState *bs = acb->common.bs;
	BDRVOFlameState *s = bs->opaque;
	int rv;

	oflameDbg("finish callback in non-QEMU context... writing on pipe\n");
	acb->ret = ret;
	rv = qemu_write_full(s->fds[VDISK_FD_WRITE], &acb, sizeof(acb));
	if (rv != sizeof(acb)) {
		error_report("OFlame AIO completion failed: %s", strerror(errno));
		abort();
	}
//	oflameDbg("returning..\n");
}

/*
 * This allocates QEMU-OFLAME callback for each IO
 * and passed to Iridium. When Iridium completed the work,
 * it will be passed back through the callback
 */

BlockDriverAIOCB *oflame_aio_rw(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque, int write)
{
	int ret;
	OFlameAIOCB *acb;
	BDRVOFlameState *s = bs->opaque;
	size_t size;
	uint64_t offset;
	int flags = 0;

//	oflameDbg("Initiating IO on vDisk\n");
	offset = sector_num * BDRV_SECTOR_SIZE;
	size = nb_sectors * BDRV_SECTOR_SIZE;

	acb = qemu_aio_get(&oflame_aio_pool, bs, cb, opaque);
	acb->size = size;
	acb->ret = 0;
	acb->aio_done = OFLAME_IO_INPROGRESS;
	acb->segments = 0;
	acb->seg_lock = SPIN_LOCK_UNLOCKED;
	flags = 0x0011;		/* IIO_FLAG_DONE = 0x0010	*/
	if (size > QEMUIRD_MAX_IO_SIZE)
	{
		oflameDbg(" JUMBO Read/Write = %d size = %d offset = %lu ACB = %p Segments = %d\n", write, nb_sectors * BDRV_SECTOR_SIZE, offset, acb, qiov->niov);
	}
	if (write == VDISK_AIO_WRITE)
	{
		oflame_inc_acb_segments(acb, 1, offset);
		oflameDbg("WRITING: opaque = %p size = %lu offset = %lu  Segments = %d\n", opaque, size, sector_num * BDRV_SECTOR_SIZE, acb->segments);
		ret = (*irdops.qemu_iio_writev)(s->ird_ctx, s->rfd, qiov->iov, qiov->niov, offset, (void *)acb, flags); 
	} else {
		oflame_inc_acb_segments(acb, qiov->niov, offset);
		oflameDbg("READING : buf = %p size = %lu offset = %lu  Segments = %d\n", buf, size, sector_num * BDRV_SECTOR_SIZE, acb->segments);
		ret = (*irdops.qemu_iio_readv)(s->ird_ctx, s->rfd, qiov->iov, qiov->niov, offset, (void *)acb, flags); 
	}
//	oflameDbg("READ/WRITE = %d , outstanding IO = %d..\n", write, s->vdisk_aio_count);

	if (ret != 0)
	{
		oflameDbg("IO ERROR FOR : Read/Write = %d size = %d offset = %lu ACB = %p Segments = %d. Error = %d\n", write, nb_sectors * BDRV_SECTOR_SIZE, sector_num * BDRV_SECTOR_SIZE, acb, acb->segments, ret);
		qemu_aio_release(acb);
		return NULL;
	}
	s->vdisk_aio_count++;
	return &acb->common;
}

/*
 * This is called from qemu-img utility when user want to resize
 * the disk
 */

int oflame_truncate(BlockDriverState *bs, int64_t offset)
{
	int ret;
	BDRVOFlameState *s = bs->opaque;

	oflameDbg("Truncating vDisk\n");
	ret = qemu_submit_io(s, NULL, 0, offset,
			     VDISK_TRUNC, (qemu_aio_ctx_t) NULL);
	oflameDbg("returning, ret = %d\n", ret);
	return ret;
}

BlockDriverAIOCB *oflame_aio_readv(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque)
{
	return oflame_aio_rw(bs, sector_num, qiov, nb_sectors, cb, opaque, 0);
}

BlockDriverAIOCB *oflame_aio_writev(BlockDriverState *bs,
		int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
		BlockDriverCompletionFunc *cb, void *opaque)
{
//	oflameDbg("WRITING: opaque = %p size = %d offset = %lu \n", opaque, nb_sectors * BDRV_SECTOR_SIZE, sector_num);
	return oflame_aio_rw(bs, sector_num, qiov, nb_sectors, cb, opaque, 1);
}

/*
 * This is called by QEMU when flush inside guest triggered at block layer
 * either for IDE or SCSI disks.
 */

static int oflame_co_flush(BlockDriverState *bs)
{
	BDRVOFlameState *s = bs->opaque;
	int opcode = VDISK_AIO_FLUSH;
	int32_t flags = 0;	/* We dont want to do ASYNC */
	uint64_t size = 0;
	int ret;

	ret = (*irdops.qemu_iio_ioctl)(s->ird_ctx, s->rfd, opcode, &size, NULL, flags); 
	if (ret < 0) {
		goto out;
	}
	if (s->vdisk_aio_count > 0)
	{
		oflameDbg("In the flush the IO count = %d \n", s->vdisk_aio_count);
	}
	return ret;	
out:
	oflameDbg("returning from FLUSH because of error = %d..\n", ret);
	return ret;

}

BlockDriverAIOCB *oflame_aio_flush(BlockDriverState *bs,
		BlockDriverCompletionFunc *cb, void *opaque)
{
	int ret = -1;
	OFlameAIOCB *acb;
	BDRVOFlameState *s = bs->opaque;
	int opcode = VDISK_AIO_FLUSH;
	int32_t flags = 1;
	uint64_t size = 0;

	//oflameDbg("flushing vDisk\n");
	acb = qemu_aio_get(&oflame_aio_pool, bs, cb, opaque);
	acb->size = 0;
	acb->ret = 0;
	acb->aio_done = OFLAME_IO_INPROGRESS;
	acb->segments = 1;

	ret = (*irdops.qemu_iio_ioctl)(s->ird_ctx, s->rfd, opcode, &size, acb, flags); 
	if (ret < 0) {
		goto out;
	}
	oflameDbg("returning from FLUSH\n");
	s->vdisk_aio_count++;
	return &acb->common;

out:
	qemu_aio_release(acb);
	oflameDbg("returning from FLUSH because of error..\n");
	return NULL;
}

/*
 * This is called by guest or QEMU to free blocks.
 * When block freed when files deleted in the guest, fstrim utility
 * can be used to pass the hints to the block layer if the disk supports
 * TRIM. It send WRITE_SAME SCSI command to QEMU virtio-scsi layer, which
 * call bdrv_aio_discard interface.
 */

/*BlockDriverAIOCB* oflame_co_discard(BlockDriverState *bs, int64_t sector_num,
                                            int nb_sectors, BlockDriverCompletionFunc *cb,
                                            void *opaque)
*/
static coroutine_fn int oflame_co_discard(BlockDriverState *bs,
    int64_t sector_num, int nb_sectors)
{
	int ret;
	int64_t off, size;
//	OFlameAIOCB *acb;
//	int opcode = VDISK_AIO_RECLAIM;
	//BDRVOFlameState *s = bs->opaque;

	oflameDbg("Reclaiming blocks of vDisk\n");
//	acb = qemu_aio_get(&oflame_aio_pool, bs, cb, opaque);
//	acb->size = 0;
//	acb->ret = 0;
//	acb->aio_done = OFLAME_IO_INPROGRESS;
//	acb->segments = 1;
//	s->vdisk_aio_count++;

	off = sector_num * BDRV_SECTOR_SIZE;
	size = nb_sectors * BDRV_SECTOR_SIZE;

//	ret = (*irdops.qemu_iio_ioctl)(s->ird_ctx, s->rfd, opcode, &size, acb, flags); 
	oflameDbg("We are faking the discard for range off = %lu for %lu bytes \n", off, size);
	ret = 0;
	if (ret < 0) {
		goto out;
	}
	oflameDbg("returning from discard \n");
//	return &acb->common;

out:
//	s->vdisk_aio_count--;
//	qemu_aio_release(acb);
	oflameDbg("returning from discard because of error..\n");
	return ret;

}

unsigned long oflame_get_vdisk_stat(BDRVOFlameState *s)
{
	int ret = 0;
	//int opcode = IRP_VDISK_STAT;
	int opcode = VDISK_STAT;
	int flags = 0;
	unsigned long size = 0;
	void *ctx = NULL;

//	oflameDbg("getting length of vDisk\n");
	ret = (*irdops.qemu_iio_ioctl)(s->ird_ctx, s->rfd, opcode, &size, ctx, flags); 
//	oflameDbg("returning vdisk stat buf. We got = %lu\n", size);
	return size;
}

/*
 * Returns the size of vDisk in bytes. This is required
 * by QEMU block upper block layer so that it is visible to guest.
 * This must be defined interface.
 */

int64_t oflame_getlength(BlockDriverState *bs)
{
//	uint64_t size = 0x1 << 30;
	BDRVOFlameState *s = bs->opaque;

	unsigned long size_ioctl;

	if (s->vdisk_size != 0)
	{
		size_ioctl = s->vdisk_size;
	}
	else 
	{
		size_ioctl = oflame_get_vdisk_stat(s);
		s->vdisk_size = size_ioctl;
	}
	
	//oflameDbg("returning  Size ioctl = %lu\n", size_ioctl);
	return size_ioctl;		//Size in bytes
}

/*
 * Returns actual blocks allocated for the vDisk. This is required
 * by qemu-img utility.
 */

int64_t oflame_get_allocated_blocks(BlockDriverState *bs)
{
	uint64_t size = 21474836480;		// 20 GB
	oflameDbg("returning Allocated blocks  = %lu \n", size);
	return size;		//Size in bytes
}

void oflame_close(BlockDriverState *bs)
{
	BDRVOFlameState *s = bs->opaque;

	oflameDbg("closing vDisk\n");
	close(s->fds[VDISK_FD_READ]);
	close(s->fds[VDISK_FD_WRITE]);
	
	/* clearing all the event handlers for oflame registered to QEMU */
	qemu_aio_set_fd_handler(s->fds[VDISK_FD_READ], NULL, NULL, NULL, NULL, NULL);
	if (s->uri) {
		uri_free(s->uri);
		s->uri = NULL;
	}
	irdops.qemu_iio_devclose(s->ird_ctx, s->rfd);
	irdops.qemu_iio_close(s->ird_ctx, s->ird_cfd);
	s->ird_ctx = NULL;
	oflameDbg("returning..\n");
}

static int oflame_has_zero_init(BlockDriverState *bs)
{
    /* Oflame volume could be backed by a block device */
    oflameDbg("returning without anything in oflame_has_zero_init..\n");
    return 0;
}


static BlockDriver bdrv_oflame = {
	.format_name                  = "oflame",
	.protocol_name                = "oflame",
	.instance_size                = sizeof(BDRVOFlameState),
	.bdrv_file_open               = oflame_open,
	.bdrv_close                   = oflame_close,
	.bdrv_getlength               = oflame_getlength,
	.bdrv_get_allocated_file_size = oflame_get_allocated_blocks,
	.bdrv_truncate                = oflame_truncate,
	.bdrv_aio_readv               = oflame_aio_readv,
	.bdrv_aio_writev              = oflame_aio_writev,
	.bdrv_co_flush               = oflame_co_flush,
	.bdrv_co_discard	      = oflame_co_discard,	
    	.bdrv_has_zero_init           = oflame_has_zero_init,
};

void bdrv_oflame_init(void)
{
	oflameDbg("Registering OFlame 8860 -debug driver\n");
	bdrv_register(&bdrv_oflame);
}

/*
 * The line below is how our drivier is initialized.
 * DO NOT TOUCH IT
 */
block_init(bdrv_oflame_init);
