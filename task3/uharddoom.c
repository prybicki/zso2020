#include <linux/printk.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/bits.h>
#include <linux/semaphore.h>

#include <linux/vmalloc.h>
#include "uharddoom.h"
#include "udoomfw.h"
#include "udoomdev.h"

///////////////////////////////////////////////////////////////////////////////
// Assumptions & decisions
/*
- Buffer's file private data = Buffer*
*/

_Static_assert(sizeof(dma_addr_t) == 8, "system does not support 40-bit dma addresses");
#define PAGE_ENTRIES 1024
#define UDOOMDEV_DMA_MASK (DMA_BIT_MASK(40))

///////////////////////////////////////////////////////////////////////////////
// Structs

struct DeviceCtx {
	struct semaphore free;
	struct mutex contexts_mutex;
	struct list_head contexts; // struct AddressSpace

	// These fields are written only in probe.
	size_t index;
	struct cdev cdev;
	struct device* sysfs;
	struct pci_dev* pci_dev;
	void __iomem* iomem;

	bool pci_enable_device_done;
	bool pci_request_regions_done;
	bool pci_set_master_done;
	bool request_irq_done;
	bool cdev_add_done;
	// pci_iomap_done == iomem;
	// device_create_done == sysfs;
	
};

typedef uint32_t dev_addr_t;

typedef struct { uint32_t value; } page_dir_entry_t;
typedef struct { uint32_t value; } page_tab_entry_t;
_Static_assert(sizeof(page_dir_entry_t) == sizeof(uint32_t), "compiler could not resist pointless padding");
_Static_assert(sizeof(page_tab_entry_t) == sizeof(uint32_t), "compiler could not resist pointless padding");

struct PageDir {
	page_dir_entry_t entry[PAGE_ENTRIES];
};

struct PageTab {
	page_tab_entry_t entry[PAGE_ENTRIES];
};

struct AddressSpace {
	struct DeviceCtx* dev;
	struct list_head list_node; // DeviceCtx.contexts
	struct file* file;
	volatile bool broken;

	struct mutex buffers_mutex;
	struct list_head buffers; // struct Buffer

	// VMem things should be protected by device's semaphore
	struct list_head areas; // struct VirtArea
	struct PageTab* pgts[PAGE_ENTRIES];
	struct PageDir* pgd; // allocated with dma_alloc_coherent
	dma_addr_t pgd_dma;
};

struct BufferPage {
	void* hst_addr;
	dma_addr_t dma_addr;
};

struct Buffer {
	struct AddressSpace* ctx;
	struct list_head list_node; // AddressSpace.buffers
	struct file* filp;
	int fd; // debug

	uint32_t size;
	struct BufferPage* pages; // array of pages with count determined by buffer size
};

struct VirtArea {
	struct Buffer* buffer;
	struct list_head list_node; // AddressSpace.areas

	dev_addr_t beg;
	dev_addr_t end;
	bool writable;
};

///////////////////////////////////////////////////////////////////////////////
// Callable

// #define dbg(fmt, ...) printk(KERN_NOTICE "uharddoom@%03d: " fmt, __LINE__, ##__VA_ARGS__)
#define dbg(...)
#define cry(fn, value) dbg("%s(...) failed with %lld\n", #fn, (long long) value)
#define W(reg, data) iowrite32(data, (void*) (((char*) dev->iomem) + reg))
#define R(reg) ioread32((void*) (((char*) dev->iomem) + reg))

int drv_initialize(void);
void drv_terminate(void);

int dev_probe(struct pci_dev *dev, const struct pci_device_id *id);
void dev_remove(struct pci_dev *dev);
int dev_suspend(struct pci_dev *dev, pm_message_t state);
int dev_resume(struct pci_dev *dev);
void dev_shutdown(struct pci_dev *dev);
irqreturn_t dev_handle_irq(int irq, void* dev);

static struct DeviceCtx* dev_alloc(struct pci_dev* pci_dev);
// static void dev_free(struct DeviceCtx* dev);
static int dev_init_pci(struct DeviceCtx* dev);
static int dev_init_dma(struct DeviceCtx* dev);
static int dev_init_irq(struct DeviceCtx* dev);
static int dev_init_hardware(struct DeviceCtx* dev, bool load_fw);
static int dev_init_chardev(struct DeviceCtx* dev);
static void dev_dbg_status(struct DeviceCtx* dev, uint32_t flags);

int  ctx_open(struct inode *, struct file *);
long ctx_ioctl(struct file *, unsigned int, unsigned long);
int  ctx_release(struct inode *, struct file *);
long ctx_ioctl_create_buffer(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_create_buffer *cmd);
long ctx_ioctl_map_buffer(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_map_buffer *cmd);
long ctx_ioctl_unmap_buffer(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_unmap_buffer *cmd);
long ctx_ioctl_run(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_run *cmd);
long ctx_ioctl_wait(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_wait *cmd);

static long ctx_ioctl_debug(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_debug *cmd);
static bool ctx_find_free_area(struct AddressSpace* ctx, size_t size, dev_addr_t* out, struct list_head **pos);
static long ctx_map_area(struct AddressSpace* ctx, struct VirtArea* area);
static void ctx_unmap_area(struct AddressSpace* ctx, struct VirtArea* area);
static void ctx_dbg_vmem(struct AddressSpace *ctx, struct udoomdev_ioctl_debug *cmd);
static void ctx_drop(struct DeviceCtx* dev, struct AddressSpace* ctx);

int buffer_release(struct inode *, struct file *);
int buffer_mmap(struct file *, struct vm_area_struct *);
vm_fault_t buffer_fault(struct vm_fault *vmf);
static void buffer_drop(struct Buffer *buff, bool);

///////////////////////////////////////////////////////////////////////////////
// Oneliners

dev_addr_t page_dir_beg(size_t dir_idx) {
	return dir_idx << 22;
}

dev_addr_t page_tab_beg(size_t dir_idx, size_t tab_idx) {
	return dir_idx << 22 | tab_idx << 12;
}

bool page_dir_is_present(page_dir_entry_t entry) {
	return (__le32_to_cpu(entry.value) & 0x1) != 0;
}

dma_addr_t page_dir_tab_addr(page_dir_entry_t entry) {
	return (dma_addr_t) ((__le32_to_cpu(entry.value) >> 4) << PAGE_SHIFT);
}

size_t page_dir_index(dev_addr_t dev_addr) {
	return (size_t) ((dev_addr & GENMASK(31, 22)) >> 22);
}

size_t page_tab_index(dev_addr_t dev_addr) {
	return (size_t) ((dev_addr & GENMASK(21, 12)) >> 12);
}

size_t page_offset(dev_addr_t dev_addr) {
	return (size_t) ((dev_addr & GENMASK(11, 0)));
}

page_dir_entry_t page_dir_make(dma_addr_t page_tab_addr) {
	return (page_dir_entry_t) {
		.value = __cpu_to_le32((page_tab_addr >> 8) | 0x1)
	};
}

bool page_tab_is_present(page_tab_entry_t entry) {
	return (__le32_to_cpu(entry.value) & 0x1) != 0;
}

bool page_tab_is_writable(page_tab_entry_t entry) {
	return (__le32_to_cpu(entry.value) & 0x2) != 0;
}

dma_addr_t page_tab_dma_addr(page_tab_entry_t entry) {
	return (dma_addr_t) ((__le32_to_cpu(entry.value) >> 4) << PAGE_SHIFT);
}

page_tab_entry_t page_tab_make(dma_addr_t dma_addr, bool writable) {
	return (page_tab_entry_t) {
		.value = __cpu_to_le32((dma_addr >> 8) | (writable ? 0x2 : 0) | 0x1)
	};
}

size_t page_cnt(size_t bytes) {
	return (bytes - 1) / PAGE_SIZE + 1;
}

///////////////////////////////////////////////////////////////////////////////
// Constants

#define MAX_DEVICE_COUNT 256
#define DRIVER_NAME "uharddoom"

const struct pci_device_id known_devices[] = {
	{PCI_DEVICE(UHARDDOOM_VENDOR_ID, UHARDDOOM_DEVICE_ID)}, 
	{0}
};

struct class device_class = {
	.name = "uharddoom",
	.owner = THIS_MODULE,
};

struct pci_driver driver_api = {
	.name = DRIVER_NAME,
	.id_table = known_devices,
	.probe    = dev_probe,
	.remove   = dev_remove,
	.suspend  = dev_suspend,
	.resume   = dev_resume,
	.shutdown = dev_shutdown
};

struct file_operations chardev_api = {
	.owner = THIS_MODULE,
	.open           = ctx_open,
	.release        = ctx_release,
	.compat_ioctl   = ctx_ioctl,
	.unlocked_ioctl = ctx_ioctl,
};

struct file_operations buffer_api = {
	.owner = THIS_MODULE,
	.release = buffer_release,
	.mmap = buffer_mmap,
};

struct vm_operations_struct buffer_vm_api = {
	.fault = buffer_fault,
};

///////////////////////////////////////////////////////////////////////////////
// Globals

dev_t devt_base;
bool pci_register_driver_done;
bool class_register_done;

DEFINE_MUTEX(devices_mutex);
struct DeviceCtx* devices[MAX_DEVICE_COUNT];

///////////////////////////////////////////////////////////////////////////////
// Driver code

int drv_initialize(void)
{
	int error = 0;

	dbg("initialization started, build %s %s\n", __DATE__, __TIME__);

	error = alloc_chrdev_region(&devt_base, 0, MAX_DEVICE_COUNT, DRIVER_NAME);
	if (error) {
		cry(alloc_chrdev_region, error);
		goto failed;
	}
	dbg("got devt_base: %d %d\n", MAJOR(devt_base), MINOR(devt_base));

	error = class_register(&device_class);
	if (error) {
		cry(class_register, error);
		goto failed;
	}
	class_register_done = true;

	// dev_probe may be called from this point
	error = pci_register_driver(&driver_api);
	if (error) {
		cry(pci_register_driver, error);
		goto failed;
	}
	pci_register_driver_done = true;

	dbg("initialization done\n");
	return error;

failed:
	drv_terminate();
	return error;
}

void drv_terminate(void)
{
	size_t i = 0;
	dbg("driver termination started\n");

	for (i = 0; i < MAX_DEVICE_COUNT; i++) {
		if (devices[i] != NULL) {
			dev_remove(devices[i]->pci_dev); // lock inside
		}
	}

	if (pci_register_driver_done) {
		pci_unregister_driver(&driver_api);
		pci_register_driver_done = false;
	}

	if (class_register_done) {
		class_unregister(&device_class);
		class_register_done = false;
	}

	if (devt_base) {
		unregister_chrdev_region(devt_base, MAX_DEVICE_COUNT);
		devt_base = 0;
	}

	dbg("driver termination done\n");
}

///////////////////////////////////////////////////////////////////////////////
// Device code

static struct DeviceCtx* dev_alloc(struct pci_dev* pci_dev)
{
	struct DeviceCtx *status;
	size_t idx;

	if (0 != mutex_lock_interruptible(&devices_mutex)) {
		return ERR_PTR(-ERESTARTSYS);
	}

	for (idx = 0; idx < MAX_DEVICE_COUNT; ++idx) {
		if (devices[idx] == NULL) {
			break;
		}
	}
	if (idx == MAX_DEVICE_COUNT) {
		status = ERR_PTR(-ENOMEM);
		cry(dev_alloc, status);
		goto out;
	}

	status = kzalloc(sizeof(*status), GFP_KERNEL);
	if (IS_ERR_OR_NULL(status)) {
		status = ERR_PTR(-ENOMEM);
		cry(dev_alloc, status);
		goto out;
	}

	devices[idx] = status;
	devices[idx]->index = idx;
	devices[idx]->pci_dev = pci_dev;
	mutex_init(&devices[idx]->contexts_mutex);
	sema_init(&devices[idx]->free, 1);
	INIT_LIST_HEAD(&devices[idx]->contexts);
	pci_set_drvdata(pci_dev, devices[idx]);
out:
	mutex_unlock(&devices_mutex);
	return status;
}

static int dev_init_pci(struct DeviceCtx* dev)
{
	void* __iomem iomem = NULL;
	int error;
	

	error = pci_enable_device(dev->pci_dev);
	if (error) {
		cry(pci_enable_device, error);
		goto out;
	}
	dev->pci_enable_device_done = true;

	error = pci_request_regions(dev->pci_dev, DRIVER_NAME);
	if (error) {	
		cry(pci_request_regions, error);
		goto out;
	}
	dev->pci_request_regions_done = true;

	
	iomem = pci_iomap(dev->pci_dev, 0, UHARDDOOM_BAR_SIZE);
	if (IS_ERR_OR_NULL(iomem)) {
		error = PTR_ERR(iomem);
		cry(pci_iomap, error);
		goto out;
	}
	dev->iomem = iomem;

	BUG_ON(error);
	return error;

out:
	return error;
}

static int dev_init_dma(struct DeviceCtx* dev)
{
	int error = 0;

	pci_set_master(dev->pci_dev);
	dev->pci_set_master_done = true;

	error = pci_set_dma_mask(dev->pci_dev, UDOOMDEV_DMA_MASK);
	if (error) {
		cry(pci_set_dma_mask, error);
		goto out;
	}
	
	error = pci_set_consistent_dma_mask(dev->pci_dev, UDOOMDEV_DMA_MASK);
	if (error) {
		cry(pci_set_consistent_dma_mask, error);
		goto out;
	}

out:
	return error;
}

static int dev_init_hardware(struct DeviceCtx* dev, bool load_fw)
{
	size_t i;
	if (load_fw) {
		W(UHARDDOOM_FE_CODE_ADDR, 0);
		for (i = 0; i < ARRAY_SIZE(udoomfw); ++i) {
			W(UHARDDOOM_FE_CODE_WINDOW, udoomfw[i]);
		}
	}
	W(UHARDDOOM_RESET, UHARDDOOM_RESET_ALL);
	W(UHARDDOOM_INTR, UHARDDOOM_INTR_MASK);
	W(UHARDDOOM_INTR_ENABLE, (UHARDDOOM_INTR_MASK & (~UHARDDOOM_INTR_BATCH_WAIT)));
	W(UHARDDOOM_ENABLE, (UHARDDOOM_ENABLE_ALL & (~UHARDDOOM_ENABLE_BATCH)));
	return 0;
}

static int dev_init_chardev(struct DeviceCtx* dev)
{
	struct device* parent_dev = NULL;
	struct device* sysfs = NULL;
	dev_t devt = devt_base + dev->index;
	int error = 0;

	cdev_init(&dev->cdev, &chardev_api);
	dev->cdev.owner = THIS_MODULE;

	error = cdev_add(&dev->cdev, devt, 1);
	if (error) {
		cry(cdev_add, error);
		goto out;
	}
	dev->cdev_add_done = true;

	parent_dev = &dev->pci_dev->dev;
	sysfs = device_create(&device_class, parent_dev, devt, NULL, "udoom%zd", dev->index);
	if (IS_ERR_OR_NULL(sysfs)) {
		error = PTR_ERR(sysfs);
		cry(device_create, error);
		goto out;
	}
	dev->sysfs = sysfs;

	dbg("device registered: %d %d", MAJOR(devt), MINOR(devt));
out:
	return error;
}

static int dev_init_irq(struct DeviceCtx* dev)
{
	int error = 0;

	error = request_irq(dev->pci_dev->irq, dev_handle_irq, IRQF_SHARED, DRIVER_NAME, dev);
	if (error) {
		cry(request_irq, error);
		goto out;
	}
	dev->request_irq_done = true;

out:
	return error;
}

struct AddressSpace* dev_get_ctx(struct DeviceCtx* dev)
{
	struct AddressSpace* ctx = NULL;
	dma_addr_t pgd_dma = R(UHARDDOOM_TLB_USER_PDP) << 12;

	list_for_each_entry(ctx, &dev->contexts, list_node) {
		if (ctx->pgd_dma == pgd_dma) {
			return ctx;
		}
	}
	BUG();
}

irqreturn_t dev_handle_irq(int irq, void* opaque)
{
	struct DeviceCtx* dev = (struct DeviceCtx*) opaque;
	uint32_t intr = 0;
	uint32_t done = 0;
	uint32_t fe_code = 0, fe_a = 0, fe_b = 0;
	uint32_t pf_addr = 0;
	int i = 0;

	intr = R(UHARDDOOM_INTR);

	if (intr & UHARDDOOM_INTR_JOB_DONE) {
		dbg("irq: job done\n");
		done |= UHARDDOOM_INTR_JOB_DONE;
	}

	if (intr & UHARDDOOM_INTR_FE_ERROR) {
		fe_code = R(UHARDDOOM_FE_ERROR_CODE);
		fe_a = R(UHARDDOOM_FE_ERROR_DATA_A);
		fe_b = R(UHARDDOOM_FE_ERROR_DATA_B);
		dbg("irq: fe error: code=0x%x a=0x%x b=0x%x\n", fe_code, fe_a, fe_b);

		dev_get_ctx(dev)->broken = true;
		dev_init_hardware(dev, false);
		done |= UHARDDOOM_INTR_FE_ERROR;
	}

	if (intr & UHARDDOOM_INTR_CMD_ERROR) {
		dbg("irq: cmd error\n");

		dev_get_ctx(dev)->broken = true;
		dev_init_hardware(dev, false);
		done |= UHARDDOOM_INTR_CMD_ERROR;
	}

	for (; i < 8; ++i) {
		if (intr & UHARDDOOM_INTR_PAGE_FAULT(i)) {
			pf_addr = R(UHARDDOOM_TLB_CLIENT_VA(i));
			dbg("irq: page fault %d at addr: 0x%x\n", i, pf_addr);

			dev_get_ctx(dev)->broken = true;
			dev_init_hardware(dev, false);
			done |= UHARDDOOM_INTR_PAGE_FAULT(i);
		}
	}

	// Any interrupt implies that device is now free.
	if (done != 0) {
		W(UHARDDOOM_INTR, done);
		up(&dev->free);
	}
	return IRQ_RETVAL(done);
}

// Always called from process context, so it can sleep.
int dev_probe(struct pci_dev* pci_dev, const struct pci_device_id *id)
{
	struct DeviceCtx* dev = NULL;
	int err = 0;

	dbg("device probe beg\n");
	
	// Alloc DeviceCtx, init trivial fields
	dev = dev_alloc(pci_dev);
	if (IS_ERR_OR_NULL(dev)) {
		err = PTR_ERR(dev);
		dev = NULL;
		goto err;
	}
	
	err = dev_init_pci(dev);
	if (err) {
		goto err;
	}

	err = dev_init_dma(dev);
	if (err) {
		goto err;
	}

	err = dev_init_hardware(dev, true);
	if (err) {
		goto err;
	}

	// Documentation/PCI/pci.rst
	// Make sure the device is quiesced and does not have any 
	// interrupts pending before registering the interrupt handler.
	err = dev_init_irq(dev);
	if (err) {
		goto err;
	}

	err = dev_init_chardev(dev);
	if (err) {
		goto err;
	}

	dbg("device [%zd] probe end\n", dev->index);

	// dev_dbg_status(dev, UDOOMDEV_DEBUG_STATUS_BASIC);
	return 0;

err:
	dbg("device [%zd] probe err = %d\n", dev->index, err);
	if (dev != NULL) {
		dev_remove(pci_dev);
	}
	return err;
}

void dev_remove(struct pci_dev *pci)
{
	struct DeviceCtx* dev = pci_get_drvdata(pci);
	struct AddressSpace* ctx = NULL, *tmp_ctx = NULL;

	if (dev == NULL) {
		return;
	}

	dbg("device removal started\n");

	list_for_each_entry_safe(ctx, tmp_ctx, &dev->contexts, list_node) {
		ctx_drop(dev, ctx); // locks and removes from dev.contexts
	}

	if (dev->sysfs) {
		device_destroy(&device_class, devt_base + dev->index);
		dev->sysfs = NULL;
	}

	if (dev->cdev_add_done) {
		cdev_del(&dev->cdev);
		dev->cdev_add_done = false;
	}

	// DMA
	if (dev->pci_set_master_done) {
		pci_clear_master(pci);
		dev->pci_set_master_done = false;
	}

	// IRQ
	if (dev->request_irq_done) {
		free_irq(pci->irq, dev);
		dev->request_irq_done = false;
	}

	if (dev->iomem) {
		pci_iounmap(pci, dev->iomem);
		dev->iomem = NULL;
	}

	if (dev->pci_request_regions_done) {
		pci_release_regions(pci);
		dev->pci_request_regions_done = false;
	}

	if (dev->pci_enable_device_done) {
		pci_disable_device(pci);
		dev->pci_enable_device_done = false;
	}

	mutex_lock(&devices_mutex);
	devices[dev->index] = NULL;
	mutex_unlock(&devices_mutex);
	pci_set_drvdata(dev->pci_dev, NULL);

	kfree(dev);

	dbg("device removal done\n");
}

int dev_suspend(struct pci_dev *pci, pm_message_t state)
{
	struct DeviceCtx* dev = pci_get_drvdata(pci);

	// wait until job is done
	down(&dev->free);
	up(&dev->free);
	return 0;;
}

int dev_resume(struct pci_dev *pci)
{
	struct DeviceCtx* dev = pci_get_drvdata(pci);
	dev_init_hardware(dev, true);
	return 0;
}

void dev_shutdown(struct pci_dev *pci)
{
	struct DeviceCtx* dev = pci_get_drvdata(pci);
	// wait until job is done
	down(&dev->free);
	up(&dev->free);
}

///////////////////////////////////////////////////////////////////////////////
// Chardev interface

int ctx_open(struct inode *inode, struct file *file)
{
	struct DeviceCtx *dev = container_of(inode->i_cdev, struct DeviceCtx, cdev);
	struct AddressSpace *ctx = NULL;
	int err = 0;

	// struct AddressSpace
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ctx)) {
		err = -ENOMEM;
		cry(kzalloc, err);
		goto err;
	}
	ctx->dev = dev;
	ctx->file = file;
	file->private_data = ctx;
	mutex_init(&ctx->buffers_mutex);
	INIT_LIST_HEAD(&ctx->areas);
	INIT_LIST_HEAD(&ctx->buffers);
	INIT_LIST_HEAD(&ctx->list_node);

	// alloc PageDirectory
	ctx->pgd = dma_alloc_coherent(&dev->pci_dev->dev, sizeof(*ctx->pgd), &ctx->pgd_dma, GFP_KERNEL);
	if (IS_ERR_OR_NULL(ctx->pgd)) {
		err = -ENOMEM;
		cry(dma_alloc_coherent, err);
		goto err;
	}

	// Add ctx to device's list of contexts
	if (mutex_lock_interruptible(&dev->contexts_mutex) != 0) {
		err = -ERESTARTSYS;
		goto err;
	}
	list_add(&ctx->list_node, &dev->contexts);
	mutex_unlock(&dev->contexts_mutex);


	err = nonseekable_open(inode, file);
	if (IS_ERR_VALUE((long) err)) {
		cry(nonseekable_open, err);
		goto err;
	}
	return 0;
err:
	if (ctx != NULL) {
		ctx_drop(dev, ctx);
	}
	return err;
}


int ctx_release(struct inode *inode, struct file *file)
{
	struct AddressSpace* ctx = file->private_data;
	struct DeviceCtx* dev = ctx->dev;
	ctx_drop(dev, ctx);
	return 0;
}

static void ctx_drop(struct DeviceCtx* dev, struct AddressSpace* ctx)
{
	struct VirtArea* area = NULL, *tmp_area = NULL;
	struct Buffer* buff = 0, *tmp_buff = NULL;
	size_t i = 0;

	dbg("ctx_drop: entry\n");

	// guarantees that device is not using mappings we're about to free
	down(&ctx->dev->free);

	list_for_each_entry_safe(area, tmp_area, &ctx->areas, list_node) {
		list_del(&area->list_node);
		kfree(area);
	}

	list_for_each_entry_safe(buff, tmp_buff, &ctx->buffers, list_node) {
		buffer_drop(buff, false); // locks and removes it from ctx.buffers
	}

	// Free page tables
	if (ctx->pgd != NULL) {
		for (i = 0; i < PAGE_ENTRIES; ++i) {
			if (ctx->pgts[i] != NULL) {
				dma_free_coherent(&dev->pci_dev->dev, sizeof(*ctx->pgts[i]), 
					ctx->pgts[i], page_dir_tab_addr(ctx->pgd->entry[i])
				);
			}
		}
		dma_free_coherent(&dev->pci_dev->dev, sizeof(*ctx->pgd), 
					ctx->pgd, ctx->pgd_dma
		);
	}

	// Remove from the device's list of contexts
	if (!list_empty(&ctx->list_node)) {
		mutex_lock(&dev->contexts_mutex);
		list_del(&ctx->list_node);
		mutex_unlock(&dev->contexts_mutex);
	}
	up(&ctx->dev->free);
	kfree(ctx);

	dbg("ctx_drop: done\n");
}

long ctx_ioctl_create_buffer(struct DeviceCtx* dev, struct AddressSpace* ctx, struct udoomdev_ioctl_create_buffer* cmd)
{
	struct Buffer* buff = NULL;
	struct fd fd;
	long err = 0;
	size_t i = 0;

	if (cmd->size == 0) {
		return -EINVAL;
	}

	// struct Buffer
	buff = kzalloc(sizeof(*buff), GFP_KERNEL);
	if (IS_ERR_OR_NULL(buff)) {
		err = -ENOMEM;
		cry(kzalloc, err);
		goto err;
	}

	// Page array
	buff->pages = kzalloc(page_cnt(cmd->size) * sizeof(struct BufferPage), GFP_KERNEL);
	if (IS_ERR_OR_NULL(buff->pages)) {
		err = -ENOMEM;
		cry(kzalloc, err);
		goto err;
	}

	// Physical memory
	for (i = 0; i < page_cnt(cmd->size); ++i) {
		buff->pages[i].hst_addr = dma_alloc_coherent(
			&dev->pci_dev->dev, PAGE_SIZE, &buff->pages[i].dma_addr, GFP_KERNEL
		);
		if (IS_ERR_OR_NULL(buff->pages[i].hst_addr)) {
			buff->pages[i].hst_addr = NULL;
			err = -ENOMEM;
			cry(dma_alloc_coherent, err);
			goto err;
		}
	}
	
	// Get fd, set private_data
	buff->fd = anon_inode_getfd(THIS_MODULE->name, &buffer_api, buff, O_RDWR);
	if (IS_ERR_VALUE((long) buff->fd)) {
		err = buff->fd;
		buff->fd = 0;
		cry(anon_inode_getfd, err);
		goto err;
	}

	fd = fdget(buff->fd);
	if (IS_ERR_OR_NULL(fd.file)) {
		err = -EBADF; // This should not happen, maybe BUG_ON would be better.
		cry(fdget, err);
		goto err;
	}
	buff->filp = fd.file;
	fdput(fd);

	buff->ctx = ctx;
	buff->size = cmd->size;
	INIT_LIST_HEAD(&buff->list_node);

	// Add buff to context's list of buffers
	if (mutex_lock_interruptible(&ctx->buffers_mutex) != 0) {
		err = -ERESTARTSYS;
		goto err;
	}

	get_file(ctx->file); // inc context refcount
	list_add(&buff->list_node, &ctx->buffers);
	mutex_unlock(&ctx->buffers_mutex);

	BUG_ON(err);
	return buff->fd;
err:
	if (buff != NULL) {
		buffer_drop(buff, true);
	}
	return err;
}

long ctx_ioctl_map_buffer(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_map_buffer *cmd)
{
	struct list_head* pred_head = NULL;
	struct VirtArea* area = NULL;
	struct Buffer* buff = NULL;
	dev_addr_t dev_addr = 0;
	uint64_t end64 = 0;
	long status = 0;
	struct fd fd = {0};

	if (down_interruptible(&dev->free)) {
		return -ERESTARTSYS;
	}

	if (ctx->broken) {
		up(&dev->free);
		return -EIO;
	}

	fd = fdget(cmd->buf_fd);
	if (IS_ERR_OR_NULL(fd.file)) {
		status = -EBADF;
		cry(fdget, status);
		goto out;
	}
	
	buff = fd.file->private_data;
	if (buff == NULL || fd.file->f_op != &buffer_api) {
		status = -ENOENT;
		dbg("map_buffer: fd is not a buffer\n");
		goto err;
	}

	// Check if given buffer belongs to the ioctl's context
	if (buff->ctx != ctx) {
		status = -ENOENT;
		dbg("map_buffer: buffer belongs to a different context\n");
		goto err;
	}

	dbg("map_buffer: fd=%u writable=%u\n", cmd->buf_fd, !cmd->map_rdonly);
	if (!ctx_find_free_area(ctx, buff->size, &dev_addr, &pred_head)) {
		status = -ENOMEM;
		cry(ctx_find_free_area, status);
		goto err;
	}

	dbg("map_buffer: mapping %u -> 0x%x\n", cmd->buf_fd, dev_addr);
	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (IS_ERR_OR_NULL(area)) {
		status = -ENOMEM;
		cry(kzalloc, status);
		goto err;
	}

	end64 = (uint64_t) dev_addr + (uint64_t) buff->size;
	if (end64 > U32_MAX) {
		status = -ENOMEM;
		dbg("map_buffer: free dev addr + buff size would overflow\n");
		goto err;
	}
	
	area->buffer = buff;
	area->beg = dev_addr;
	area->end = dev_addr + buff->size;
	area->writable = !cmd->map_rdonly;
	INIT_LIST_HEAD(&area->list_node);

	status = ctx_map_area(ctx, area);
	if (IS_ERR_VALUE(status)) {
		goto err;
	}
	get_file(buff->filp); // inc buffer refcount
	
	list_add(&area->list_node, pred_head);
	
	BUG_ON(status);
	status = dev_addr;
	goto out;

err:
	if (status == -ERESTARTSYS) {
		return status;
	}
	if (area != NULL) {
		kfree(area);
	}
out:
	fdput(fd);
	up(&dev->free);
	return status;
}

static long ctx_map_area(struct AddressSpace* ctx, struct VirtArea* area)
{
	struct PageTab* page_tab = NULL;
	dma_addr_t page_tab_dma = 0;
	size_t page_idx = 0;
	size_t dir_idx = 0;
	size_t tab_idx = 0;
	long err = 0;
	BUG_ON(page_offset(area->beg) != 0);

	dbg("map_area: area: (0x%x, 0x%x) w=%u\n", area->beg, area->end, area->writable);
	for (; page_idx < page_cnt(area->buffer->size); page_idx += 1) {
		dir_idx = page_dir_index(area->beg + page_idx * PAGE_SIZE);
		tab_idx = page_tab_index(area->beg + page_idx * PAGE_SIZE);

		// make sure page table is present:
		if (IS_ERR_OR_NULL(ctx->pgts[dir_idx])) {
			dbg("ctx_map_area: allocating page table [%zu]\n", dir_idx);
			page_tab = dma_alloc_coherent(&ctx->dev->pci_dev->dev, sizeof(*page_tab), &page_tab_dma, GFP_KERNEL);
			if (IS_ERR_OR_NULL(page_tab)) {
				cry(dma_alloc_coherent, -ENOMEM);
				err = -ENOMEM;
				goto err;
			}
			ctx->pgts[dir_idx] = page_tab;
			ctx->pgd->entry[dir_idx] = page_dir_make(page_tab_dma);
		}
		dbg("map_area: updating dir_idx=%zu tab_idx=%zu\n", dir_idx, tab_idx);
		ctx->pgts[dir_idx]->entry[tab_idx] = page_tab_make(area->buffer->pages[page_idx].dma_addr, area->writable);
	}
	return 0;

err:
	// Do not deallocate PageTabs, just zero already allocated entries.
	ctx_unmap_area(ctx, area);
	return err;
}

bool ctx_find_free_area(struct AddressSpace* ctx, size_t size, dev_addr_t* out, struct list_head **pos)
{
	struct list_head *curr = &ctx->areas;
	struct list_head *next = ctx->areas.next;
	struct VirtArea* curr_entry = NULL;
	struct VirtArea* next_entry = NULL;
	dev_addr_t hole_beg = 0;
	dev_addr_t hole_end = 0;

	if (list_empty(&ctx->areas)) {
		*out = 0;
		*pos = &ctx->areas;
		return true;
	}

	// Consider holes between curr and next.
	do {
		curr_entry = (curr == &ctx->areas) ? NULL : list_entry(curr, struct VirtArea, list_node);
		next_entry = (next == &ctx->areas) ? NULL : list_entry(next, struct VirtArea, list_node);

		hole_beg = curr_entry == NULL ? 0 : curr_entry->end;
		hole_end = next_entry == NULL ? UINT_MAX : next_entry->beg;
		
		if (hole_end - hole_beg >= size) {
			*out = hole_beg;
			*pos = curr;
			return true;
		}

		curr = next;
		next = next->next;
	}
	while (curr != &ctx->areas);

	return false;
}

long ctx_ioctl_unmap_buffer(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_unmap_buffer *cmd)
{
	struct VirtArea *area = NULL, *tmp = NULL;
	dev_addr_t addr = cmd->addr;
	long err = 0;

	dbg("unmap_buffer: entry\n");

	if (down_interruptible(&dev->free)) {
		return -ERESTARTSYS;
	}

	list_for_each_entry_safe(area, tmp, &ctx->areas, list_node) {
		if (area->beg == addr) {
			ctx_unmap_area(ctx, area);
			fput(area->buffer->filp);
			dbg("removing area: buff: %d, (0x%x, 0x%x) %d\n", area->buffer->fd, area->beg, area->end, area->writable);
			list_del(&area->list_node);
			kfree(area);
			goto done;
		}
	}
	err = -ENOENT;
	dbg("unmap_buffer: err\n");

done:
	up(&dev->free);
	dbg("unmap_buffer: done\n");
	return err;
}

// This does not remove Virt Area and does not affect buffer.
static void ctx_unmap_area(struct AddressSpace* ctx, struct VirtArea* area)
{
	size_t dir_idx = 0;
	size_t tab_idx = 0;
	size_t offset = 0;

	for (; offset < area->buffer->size; offset += PAGE_SIZE) {
		dir_idx = page_dir_index(area->beg + offset);
		tab_idx = page_tab_index(area->beg + offset);

		if (ctx->pgts[dir_idx] != NULL) {
			dbg("unmapping dir_idx=%zu tab_idx=%zu\n", dir_idx, tab_idx);
			ctx->pgts[dir_idx]->entry[tab_idx].value = __cpu_to_le32(0);
		}
	}
}

static void buffer_drop(struct Buffer *buff, bool dec_refcount)
{
	size_t i = 0;
	dbg("buffer_drop: entry\n");
	// Free underlying memory
	if (buff->pages != NULL) {
		for (i = 0; i < page_cnt(buff->size); i++) {
			if (buff->pages[i].hst_addr != NULL) {
				dma_free_coherent(&buff->ctx->dev->pci_dev->dev, 
					PAGE_SIZE, buff->pages[i].hst_addr, buff->pages[i].dma_addr
				);
			}
		}
		kfree(buff->pages);
	}

	// Remove buff from context's list of buffers
	if (!list_empty(&buff->list_node)) {
		mutex_lock(&buff->ctx->buffers_mutex);
		list_del(&buff->list_node);
		mutex_unlock(&buff->ctx->buffers_mutex);
	}
	if (dec_refcount) {
		fput(buff->ctx->file); // dec refcount
	}
	kfree(buff);
	dbg("buffer_drop: done\n");

}

long ctx_ioctl_run(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_run *cmd)
{
	dbg("run: entry\n");
	if (!IS_ALIGNED(cmd->addr, 4) || !IS_ALIGNED(cmd->size, 4)) {
		return -EINVAL;
	}

	if (down_interruptible(&dev->free)) {
		return -ERESTARTSYS;
	}

	if (ctx->broken) {
		up(&dev->free);
		return -EIO;
	}
	
	dbg("run: trig\n");

	W(UHARDDOOM_JOB_PDP, (ctx->pgd_dma >> 12));
	W(UHARDDOOM_JOB_CMD_PTR, cmd->addr);
	W(UHARDDOOM_JOB_CMD_SIZE, cmd->size);
	W(UHARDDOOM_JOB_TRIGGER, 1);

	// up(&dev->free) is done in irq handler.
	dbg("run: exit\n");
	return 0;
}

long ctx_ioctl_wait(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_wait *cmd)
{
	dbg("wait: entry\n");
	// Since ioctl_run is synchronous, there can be max 1 pending task
	if (cmd->num_back >= 1) {
		return 0;
	}

	if (down_interruptible(&dev->free)) {
		return -ERESTARTSYS;
	}

	if (ctx->broken) {
		up(&dev->free);
		return -EIO;
	}
	
	up(&dev->free);
	dbg("wait: exit\n");
	return 0;
}

long ctx_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	struct AddressSpace *ctx = file->private_data;
	struct DeviceCtx *dev = ctx->dev;
	union {
		struct udoomdev_ioctl_create_buffer create;
		struct udoomdev_ioctl_map_buffer map;
		struct udoomdev_ioctl_unmap_buffer unmap;
		struct udoomdev_ioctl_run run;
		struct udoomdev_ioctl_wait wait;
		struct udoomdev_ioctl_debug debug;
	} data;

	int err = 0;
	switch (cmd) {
		case UDOOMDEV_IOCTL_CREATE_BUFFER: err = copy_from_user(&data.create, (void*) args, sizeof(data.create)); break;
		case UDOOMDEV_IOCTL_MAP_BUFFER:    err = copy_from_user(&data.map,    (void*) args, sizeof(data.map)); break;
		case UDOOMDEV_IOCTL_UNMAP_BUFFER:  err = copy_from_user(&data.unmap,  (void*) args, sizeof(data.unmap)); break;
		case UDOOMDEV_IOCTL_RUN:           err = copy_from_user(&data.run,    (void*) args, sizeof(data.run)); break;
		case UDOOMDEV_IOCTL_WAIT:          err = copy_from_user(&data.wait,   (void*) args, sizeof(data.wait)); break;
		case UDOOMDEV_IOCTL_DEBUG:         err = copy_from_user(&data.debug,  (void*) args, sizeof(data.debug)); break;
	}

	if (err > 0) {
		dbg("ctx_ioctl: invalid user");
		return -EFAULT;
	}

	switch (cmd) {
		case UDOOMDEV_IOCTL_CREATE_BUFFER: return ctx_ioctl_create_buffer(dev, ctx, &data.create);
		case UDOOMDEV_IOCTL_MAP_BUFFER:    return ctx_ioctl_map_buffer(dev, ctx, &data.map);
		case UDOOMDEV_IOCTL_UNMAP_BUFFER:  return ctx_ioctl_unmap_buffer(dev, ctx, &data.unmap);
		case UDOOMDEV_IOCTL_RUN:           return ctx_ioctl_run(dev, ctx, &data.run);
		case UDOOMDEV_IOCTL_WAIT:          return ctx_ioctl_wait(dev, ctx, &data.wait);
		case UDOOMDEV_IOCTL_DEBUG:         return ctx_ioctl_debug(dev, ctx, &data.debug);
	}

	return -ENOTTY;
}

///////////////////////////////////////////////////////////////////////////////
// Buffer API

int buffer_release(struct inode* inode, struct file* filp)
{
	struct Buffer *buff = filp->private_data;
	buffer_drop(buff, true);
	return 0;
}

int buffer_mmap(struct file* filp, struct vm_area_struct* vma)
{
	dbg("buffer_mmap: %d\n", ((struct Buffer*) filp->private_data)->fd);
	vma->vm_ops = &buffer_vm_api;
	return 0; 
}

vm_fault_t buffer_fault(struct vm_fault *vmf)
{
	struct file* filp = vmf->vma->vm_file;
	struct Buffer* buff = filp->private_data;

	dbg("buffer_fault: entry (%d)\n", buff->fd);

	if (vmf->pgoff >= page_cnt(buff->size)) {
		dbg("buffer_fault: out of bounds\n");
		return VM_FAULT_SIGBUS;
	}
	vmf->page = virt_to_page(buff->pages[vmf->pgoff].hst_addr);
	get_page(vmf->page);
	dbg("buffer_fault: done\n");
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// Integration

MODULE_LICENSE("GPL");
module_init(drv_initialize);
module_exit(drv_terminate);

///////////////////////////////////////////////////////////////////////////////
// Debug

void dev_dbg_status(struct DeviceCtx* dev, unsigned flags)
{
	static uint32_t stats[UHARDDOOM_STATS_NUM];
	uint32_t status;
	size_t idx;

	status = R(UHARDDOOM_STATUS);
	for (idx = 0; idx < UHARDDOOM_STATS_NUM; ++idx) {
		stats[idx] = R(UHARDDOOM_STATS(idx));
	}

	if (flags & UDOOMDEV_DEBUG_STATUS_BASIC) {
		dbg("UHARDDOOM_STATUS_BATCH: %u\n", (status & UHARDDOOM_STATUS_BATCH));
		dbg("UHARDDOOM_STATUS_JOB: %u\n", (status & UHARDDOOM_STATUS_JOB));
		dbg("UHARDDOOM_STATUS_CMD: %u\n", (status & UHARDDOOM_STATUS_CMD));
		dbg("UHARDDOOM_STATUS_FE: %u\n", (status & UHARDDOOM_STATUS_FE));
		dbg("UHARDDOOM_STATUS_SRD: %u\n", (status & UHARDDOOM_STATUS_SRD));
		dbg("UHARDDOOM_STATUS_SPAN: %u\n", (status & UHARDDOOM_STATUS_SPAN));
		dbg("UHARDDOOM_STATUS_COL: %u\n", (status & UHARDDOOM_STATUS_COL));
		dbg("UHARDDOOM_STATUS_FX: %u\n", (status & UHARDDOOM_STATUS_FX));
		dbg("UHARDDOOM_STATUS_SWR: %u\n", (status & UHARDDOOM_STATUS_SWR));
	}

	if (flags & UDOOMDEV_DEBUG_STATUS_FIFO) {
		dbg("UHARDDOOM_STATUS_FIFO_SRDCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SRDCMD));
		dbg("UHARDDOOM_STATUS_FIFO_SPANCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANCMD));
		dbg("UHARDDOOM_STATUS_FIFO_COLCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLCMD));
		dbg("UHARDDOOM_STATUS_FIFO_FXCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXCMD));
		dbg("UHARDDOOM_STATUS_FIFO_SWRCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SWRCMD));
		dbg("UHARDDOOM_STATUS_FIFO_COLIN: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLIN));
		dbg("UHARDDOOM_STATUS_FIFO_FXIN: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXIN));
		dbg("UHARDDOOM_STATUS_FIFO_FESEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_FESEM));
		dbg("UHARDDOOM_STATUS_FIFO_SRDSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_SRDSEM));
		dbg("UHARDDOOM_STATUS_FIFO_COLSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLSEM));
		dbg("UHARDDOOM_STATUS_FIFO_SPANSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANSEM));
		dbg("UHARDDOOM_STATUS_FIFO_SPANOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANOUT));
		dbg("UHARDDOOM_STATUS_FIFO_COLOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLOUT));
		dbg("UHARDDOOM_STATUS_FIFO_FXOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXOUT));
	}

	if (flags & UDOOMDEV_DEBUG_STAT_BASIC) {
		dbg("UHARDDOOM_STAT_FW_JOB: %u\n", stats[0x00]);
		dbg("UHARDDOOM_STAT_FW_CMD: %u\n", stats[0x01]);
		dbg("UHARDDOOM_STAT_CMD_BLOCK: %u\n", stats[0x56]);
		dbg("UHARDDOOM_STAT_CMD_WORD: %u\n", stats[0x57]);
		dbg("UHARDDOOM_STAT_FE_INSN: %u\n", stats[0x58]);
		dbg("UHARDDOOM_STAT_FE_LOAD: %u\n", stats[0x59]);
		dbg("UHARDDOOM_STAT_FE_STORE: %u\n", stats[0x5a]);
		dbg("UHARDDOOM_STAT_MMIO_READ: %u\n", stats[0x5c]);
		dbg("UHARDDOOM_STAT_MMIO_WRITE: %u\n", stats[0x5d]);
		dbg("UHARDDOOM_STAT_SRD_CMD: %u\n", stats[0x60]);
	}

	if (flags & UDOOMDEV_DEBUG_STAT_EXT) {
		dbg("UHARDDOOM_STAT_SRD_READ: %u\n", stats[0x61]);
		dbg("UHARDDOOM_STAT_SRD_BLOCK: %u\n", stats[0x62]);
		dbg("UHARDDOOM_STAT_SRD_FESEM: %u\n", stats[0x63]);
		dbg("UHARDDOOM_STAT_SWR_CMD: %u\n", stats[0x78]);
		dbg("UHARDDOOM_STAT_SWR_DRAW: %u\n", stats[0x79]);
		dbg("UHARDDOOM_STAT_SWR_BLOCK: %u\n", stats[0x7a]);
		dbg("UHARDDOOM_STAT_SWR_BLOCK_READ: %u\n", stats[0x7b]);
		dbg("UHARDDOOM_STAT_SWR_BLOCK_TRANS: %u\n", stats[0x7c]);
		dbg("UHARDDOOM_STAT_SWR_SRDSEM: %u\n", stats[0x7d]);
		dbg("UHARDDOOM_STAT_SWR_COLSEM: %u\n", stats[0x7e]);
		dbg("UHARDDOOM_STAT_SWR_SPANSEM: %u\n", stats[0x7f]);
	}

}

size_t list_size(struct list_head* head)
{
	struct list_head* pos = NULL;
	size_t cnt = 0;
	list_for_each(pos, head) {
		cnt +=1 ;
	}
	return cnt;
}


static void _ctx_dbg(struct DeviceCtx* dev, struct AddressSpace* ctx)
{
	struct Buffer* buff = NULL;
	struct VirtArea* area = NULL;

	dbg("context:\n");
	list_for_each_entry(buff, &ctx->buffers, list_node) {
		dbg("buffer: %d sz=0x%x\n", buff->fd, buff->size);
	}
	list_for_each_entry(area, &ctx->areas, list_node) {
		dbg("area: (0x%x, 0x%x), buff=%d\n", area->beg, area->end, area->buffer->fd);
	}
}

static void _dev_dbg(struct DeviceCtx* dev) {
	struct AddressSpace* ctx = NULL;
	
	dbg("device:\n");
	list_for_each_entry(ctx, &dev->contexts, list_node) {
		_ctx_dbg(dev, ctx);
	}
}

static void _drv_dbg(void) 
{
	size_t d = 0;
	for (d = 0; d < MAX_DEVICE_COUNT; d++) {
		if (devices[d] != NULL) {
			_dev_dbg(devices[d]);
			dbg("\n");
		}
	}
	dbg("--- --- ---\n");
}

long ctx_ioctl_debug(struct DeviceCtx *dev, struct AddressSpace *ctx, struct udoomdev_ioctl_debug *cmd)
{
	if (cmd->flags & UDOOMDEV_DEBUG_VMEM) {
		ctx_dbg_vmem(ctx, cmd);
	}
	if (cmd->flags & UDOOMDEV_DEBUG_INTERNAL) {
		_drv_dbg();
	}
	dev_dbg_status(dev, cmd->flags);
	return 0;
}

#define print(fmt, ...) written += snprintf(output + written, UDOOMDEV_DEBUG_BUFFER_SIZE - written, fmt, ##__VA_ARGS__)
void ctx_dbg_vmem(struct AddressSpace *ctx, struct udoomdev_ioctl_debug *cmd)
{
	char *output = vzalloc(UDOOMDEV_DEBUG_BUFFER_SIZE);
	struct VirtArea* area = NULL;
	struct Buffer* buff = NULL;
	size_t i = 0, k = 0;
	size_t written = 0;
	BUG_ON(IS_ERR_OR_NULL(output));

	dbg("DEBUG VMEM\n");

	print("Buffers:\n");
	list_for_each_entry(buff, &ctx->buffers, list_node) {
		print("[%d] sz=(0x%x, %u)\n",
			buff->fd, buff->size, buff->size
		);
	}
	print("\n");

	print("VirtAreas: %px (prev=%px, next=%px)\n", &ctx->areas, ctx->areas.prev, ctx->areas.next);
	list_for_each_entry(area, &ctx->areas, list_node) {
		// dbg("area: %px\n", area);
		print("beg=0x%x end=0x%x w=%d buff=%d\n",
			area->beg, area->end, area->writable, area->buffer->fd
		);
	}
	print("\n");

	print("Page Dir: hst=%px dma=%llx\n", ctx->pgd, ctx->pgd_dma);
	for (i = 0; i < PAGE_ENTRIES; ++i) {
		if (ctx->pgd->entry[i].value != 0) {
			print("[%zu]: beg=0x%x hst=%px, dma=%llx\n",
				i, page_dir_beg(i), ctx->pgts[i], page_dir_tab_addr(ctx->pgd->entry[i])
			);
		}
	}
	print("\n");

	for (i = 0; i < PAGE_ENTRIES; ++i) {
		if (ctx->pgd->entry[i].value != 0) {
			print("Page Table[%zu]: beg=0x%x hst=%px, dma=%llx\n",
				i, page_dir_beg(i), ctx->pgts[i], page_dir_tab_addr(ctx->pgd->entry[i])
			);
			for (k = 0; k < PAGE_ENTRIES; ++k) {
				if (page_tab_is_present(ctx->pgts[i]->entry[k])) {
					print("[%zu] beg=0x%x, dma=%llx, write=%d\n",
						k, page_tab_beg(i, k), page_tab_dma_addr(ctx->pgts[i]->entry[k]), (int) page_tab_is_writable(ctx->pgts[i]->entry[k])
					);
				}
			}
			print("\n");
		}
	}
	print("\n");

	BUG_ON(copy_to_user(cmd->output, output, written));
	vfree(output);
}
#undef print
