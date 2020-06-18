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

#include "uharddoom.h"
#include "udoomfw.h"
#include "udoomdev.h"

// QUESTION Co znaczy że urządzenie obsługuje 32 bitowe wirtualne i 40 bitowe fizyczne?
// QUESTION Czy potrzebujemy używać jakichś mem-fence podczas startu urządzenia?
//          Np. po wgraniu firmware.

///////////////////////////////////////////////////////////////////////////////
// Assumptions & decisions
/*
- Buffer's file private data = Buffer*

Remove shit like (?):
mem = alloc()
if () ...
dev->mem = mem;

TODO:
Make sure to use consistently IS_ERR_OR_NULL;
Last allocation part should return 

Use __cpu_to_le32

*/

_Static_assert(sizeof(dma_addr_t) == 8, "");
#define PAGE_ENTRIES 1024
#define UDOOMDEV_DMA_MASK (DMA_BIT_MASK(40))

///////////////////////////////////////////////////////////////////////////////
// Structs

struct DeviceCtx {
	size_t index;
	struct list_head contexts; // struct AddressSpace

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

typedef struct {
	uint32_t value;
} page_tab_entry_t;

struct PageTab {
	page_tab_entry_t entry[PAGE_ENTRIES];
};

typedef struct {
	uint32_t value;
} page_dir_entry_t;

struct PageDir {
	page_dir_entry_t entry[PAGE_ENTRIES];
};

struct AddressSpace {
	struct DeviceCtx* device;
	struct list_head list_node;
	struct list_head buffers; // struct Buffer
	struct list_head areas; // struct VirtArea

	struct PageDir* pgd;
	dma_addr_t pgd_dma_addr;
	struct PageTab* pgt[PAGE_ENTRIES];
};

struct VirtArea {
	dev_addr_t beg;
	dev_addr_t end;
	struct Buffer* buffer;
	struct list_head list_node;
};

struct Buffer {
	struct AddressSpace* ctx;
	struct list_head list_node;
	uint32_t size;
	
	void* hst_addr;
	dma_addr_t dma_addr;
	dev_addr_t dev_addr;
};

///////////////////////////////////////////////////////////////////////////////
// Callable

#define dbg(fmt, ...) printk(KERN_NOTICE "uharddoom@%03d: " fmt, __LINE__, ##__VA_ARGS__)
#define cry(fn, value) dbg("%s(...) failed with %lld\n", #fn, (long long) value)
#define W(reg, data) iowrite32(data, (void*) (((char*) device->iomem) + reg))
#define R(reg) ioread32((void*) (((char*) device->iomem) + reg))

int drv_initialize(void);
void drv_terminate(void);

// Main device functions
int dev_probe(struct pci_dev *dev, const struct pci_device_id *id);
void dev_remove (struct pci_dev *dev);
int dev_suspend(struct pci_dev *dev, pm_message_t state);
int dev_resume(struct pci_dev *dev);
void dev_shutdown(struct pci_dev *dev);

// Helper device functions
struct DeviceCtx* dev_alloc(struct pci_dev* pci_dev);
void dev_free(struct DeviceCtx* device);
int dev_init_pci(struct DeviceCtx* device);
int dev_init_dma(struct DeviceCtx* device);
int dev_init_irq(struct DeviceCtx* device);
int dev_init_hardware(struct DeviceCtx* device);
int dev_init_chardev(struct DeviceCtx* device);
irqreturn_t dev_handle_irq(int irq, void* dev);
void dev_printk_status(struct DeviceCtx* device);

int  ctx_open(struct inode *, struct file *);
long ctx_ioctl(struct file *, unsigned int, unsigned long);
int  ctx_release(struct inode *, struct file *);
long ctx_ioctl_create_buffer(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_create_buffer *cmd);
long ctx_ioctl_map_buffer(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_map_buffer *cmd);
long ctx_ioctl_unmap_buffer(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_unmap_buffer *cmd);
long ctx_ioctl_run(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_run *cmd);
long ctx_ioctl_wait(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_wait *cmd);
bool ctx_find_free_area(struct AddressSpace* ctx, size_t size, dev_addr_t* out, struct list_head **pos);


int buffer_release(struct inode *, struct file *);
int buffer_mmap(struct file *, struct vm_area_struct *);
vm_fault_t buffer_host_fault(struct vm_fault *vmf);

///////////////////////////////////////////////////////////////////////////////
// Oneliners

// TODO use it:
// BUG_ON((page_tab_addr & PAGE_MASK) != 0) // must be aligned to page size
// BUG_ON((page_tab_addr & (~UDOOMDEV_DMA_MASK)) != 0) // must fit into DMA bits

bool page_dir_is_present(page_dir_entry_t entry) {
	return (entry.value & 0x1) == 1;
}

dma_addr_t page_dir_tab_addr(page_dir_entry_t entry) {
	return (dma_addr_t) ((entry.value >> 4) << PAGE_SHIFT);
}

page_dir_entry_t page_dir_make(dma_addr_t page_tab_addr) {
	return (page_dir_entry_t) {
		.value = (page_tab_addr >> 8) | 0x1
	};
}

bool page_tab_is_present(page_tab_entry_t entry) {
	return (entry.value & 0x1) == 1;
}

bool page_tab_is_writable(page_tab_entry_t entry) {
	return (entry.value & 0x2) == 1;
}

dma_addr_t page_tab_dma_addr(page_tab_entry_t entry) {
	return (dma_addr_t) ((entry.value >> 4) << PAGE_SHIFT);
}

page_tab_entry_t page_tab_make(dma_addr_t dma_addr, bool writable) {
	return (page_tab_entry_t) {
		.value = (dma_addr >> 8) | (writable ? 0x2 : 0) | 0x1
	};
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
	.mmap_supported_flags = MAP_SHARED
};

struct vm_operations_struct buffer_vm_api = {
	.fault = buffer_host_fault,
};

///////////////////////////////////////////////////////////////////////////////
// Globals

dev_t devt_base;
bool pci_register_driver_done;
bool class_register_done;

atomic_t deinitializing;
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

// TODO
void drv_terminate(void)
{
	dbg("driver termination started\n");

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

struct DeviceCtx* dev_alloc(struct pci_dev* pci_dev)
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
	if (status == NULL) {
		status = ERR_PTR(-ENOMEM);
		cry(dev_alloc, status);
		goto out;
	}

	devices[idx] = status;
	devices[idx]->index = idx;
	devices[idx]->pci_dev = pci_dev;
	INIT_LIST_HEAD(&devices[idx]->contexts);
	pci_set_drvdata(pci_dev, devices[idx]);
out:
	mutex_unlock(&devices_mutex);
	return status;
}

void dev_free(struct DeviceCtx* device)
{
	size_t idx = device->index;
	kfree(device);
	mutex_lock(&devices_mutex);
	devices[idx] = NULL;
	mutex_unlock(&devices_mutex);
}

int dev_init_pci(struct DeviceCtx* device)
{
	void* __iomem iomem = NULL;
	int error;
	

	error = pci_enable_device(device->pci_dev);
	if (error) {
		cry(pci_enable_device, error);
		goto out;
	}
	device->pci_enable_device_done = true;

	error = pci_request_regions(device->pci_dev, DRIVER_NAME);
	if (error) {	
		cry(pci_request_regions, error);
		goto out;
	}
	device->pci_request_regions_done = true;

	
	iomem = pci_iomap(device->pci_dev, 0, UHARDDOOM_BAR_SIZE);
	if (IS_ERR_OR_NULL(iomem)) {
		error = PTR_ERR(iomem);
		cry(pci_iomap, error);
		goto out;
	}
	device->iomem = iomem;

	BUG_ON(error);
	return error;

out:
	// TODO cleanup?
	return error;
}

// TODO unfinished
int dev_init_dma(struct DeviceCtx* device)
{
	int error = 0;

	// TODO: co to dokładnie robi? czy trzeba to cofać?
	pci_set_master(device->pci_dev);
	device->pci_set_master_done = true;

	// TODO czy tu jest potrzebny cleanup?
	error = pci_set_dma_mask(device->pci_dev, UDOOMDEV_DMA_MASK);
	if (error) {
		cry(pci_set_dma_mask, error);
		goto out;
	}
	
	error = pci_set_consistent_dma_mask(device->pci_dev, UDOOMDEV_DMA_MASK);
	if (error) {
		cry(pci_set_consistent_dma_mask, error);
		goto out;
	}

out:
	return error;
}

int dev_init_hardware(struct DeviceCtx* device)
{
	size_t i;
	// zapisać 0 do FE_CODE_ADDR,
	W(UHARDDOOM_FE_CODE_ADDR, 0);
	// kolejno zapisać wszystkie słowa tablicy udoomfw[] do FE_CODE_WINDOW,
	for (i = 0; i < ARRAY_SIZE(udoomfw); ++i) {
		W(UHARDDOOM_FE_CODE_WINDOW, udoomfw[i]);
	}
	// zresetować wszystkie bloki urządzenia przez zapis 0x7f7ffffe do RESET,
	W(UHARDDOOM_RESET, UHARDDOOM_RESET_ALL);
	// zainicjować BATCH_PDP, BATCH_GET, BATCH_PUT i BATCH_WRAP, jeśli chcemy użyć bloku wczytywania pleceń,
	(void) 0;
	// wyzerować INTR przez zapis 0xff33,
	W(UHARDDOOM_INTR, UHARDDOOM_INTR_MASK);
	// włączyć używane przez nas przerwania w INTR_ENABLE,
	W(UHARDDOOM_INTR_ENABLE, (UHARDDOOM_INTR_MASK & (~UHARDDOOM_INTR_BATCH_WAIT)));
	// włączyć wszystkie bloki urządzenia w ENABLE (być może z wyjątkiem BATCH).
	W(UHARDDOOM_ENABLE, (UHARDDOOM_ENABLE_ALL & (~UHARDDOOM_ENABLE_BATCH)));

	return 0;
}

int dev_init_chardev(struct DeviceCtx* device)
{
	struct device* parent_dev = NULL;
	struct device* sysfs = NULL;
	dev_t devt = devt_base + device->index;
	int error = 0;

	cdev_init(&device->cdev, &chardev_api);
	device->cdev.owner = THIS_MODULE;

	error = cdev_add(&device->cdev, devt, 1);
	if (error) {
		cry(cdev_add, error);
		goto out;
	}
	device->cdev_add_done = true;

	parent_dev = &device->pci_dev->dev;
	sysfs = device_create(&device_class, parent_dev, devt, NULL, "udoom%zd", device->index);
	if (IS_ERR_OR_NULL(sysfs)) {
		error = PTR_ERR(sysfs);
		cry(device_create, error);
		goto out;
	}
	device->sysfs = sysfs;

	dbg("device registered: %d %d", MAJOR(devt), MINOR(devt));
out:
	return error;
}

int dev_init_irq(struct DeviceCtx* device)
{
	int error = 0;

	error = request_irq(device->pci_dev->irq, dev_handle_irq, IRQF_SHARED, DRIVER_NAME, device);
	if (error) {
		cry(request_irq, error);
		goto out;
	}
	device->request_irq_done = true;

out:
	return error;
}

// TODO
irqreturn_t dev_handle_irq(int irq, void* dev)
{
	// struct DeviceCtx* device = (struct DeviceCtx*) dev;

	dbg("haha interrupt %d\n", irq);
	return IRQ_HANDLED;
	// TODO
}

// Always called from process context, so it can sleep.
int dev_probe(struct pci_dev* pci_dev, const struct pci_device_id *id)
{
	struct DeviceCtx* device = NULL;
	int error = 0;
	
	dbg("device probe started\n");

	device = dev_alloc(pci_dev);
	if (IS_ERR_OR_NULL(device)) {
		error = PTR_ERR(device);
		goto fail;
	}

	dbg("initializing device [%zd]\n", device->index);

	error = dev_init_pci(device);
	if (error) {
		goto fail;
	}

	error = dev_init_dma(device);
	if (error) {
		goto fail;
	}

	error = dev_init_hardware(device);
	if (error) {
		goto fail;
	}

	// Documentation/PCI/pci.rst
	// Make sure the device is quiesced and does not have any 
	// interrupts pending before registering the interrupt handler.
	error = dev_init_irq(device);
	if (error) {
		goto fail;
	}

	error = dev_init_chardev(device);
	if (error) {
		goto fail;
	}

	dbg("device probe done [%zd]\n", device->index);


	dev_printk_status(device);
	return 0;

fail:
	dev_remove(pci_dev);
	return error;
}


// TODO unfinished, free resources
void dev_remove(struct pci_dev *dev)
{
	struct DeviceCtx* device = pci_get_drvdata(dev);
	BUG_ON(device == NULL);

	// TODO finish tasks..
	// Think of some locking here
	// TODO ORDERING MAY BE WRONG!!!
	// Especially IRQ/DMA

	dbg("device removal started\n");

	if (device->sysfs) {
		device_destroy(&device_class, devt_base + device->index);
		device->sysfs = NULL;
	}

	if (device->cdev_add_done) {
		cdev_del(&device->cdev);
		device->cdev_add_done = false;
	}

	// DMA
	if (device->pci_set_master_done) {
		pci_clear_master(dev);
		device->pci_set_master_done = false;
	}

	// IRQ
	if (device->request_irq_done) {
		free_irq(dev->irq, device);
		device->request_irq_done = false;
	}

	if (device->iomem) {
		pci_iounmap(dev, device->iomem);
		device->iomem = NULL;
	}

	if (device->pci_request_regions_done) {
		pci_release_regions(dev);
		device->pci_request_regions_done = false;
	}

	if (device->pci_enable_device_done) {
		pci_disable_device(dev);
		device->pci_enable_device_done = false;
	}

	mutex_lock(&devices_mutex);
	devices[device->index] = NULL;
	mutex_unlock(&devices_mutex);
	pci_set_drvdata(device->pci_dev, NULL);
	kfree(device);

	dbg("device removal done\n");
}

int dev_suspend(struct pci_dev *dev, pm_message_t state)
{
	return -EIO;
}

int dev_resume(struct pci_dev *dev)
{
	return -EIO;
}

void dev_shutdown(struct pci_dev *dev)
{

}

///////////////////////////////////////////////////////////////////////////////
// Chardev interface

int ctx_open(struct inode *inode, struct file *file)
{
	struct DeviceCtx *device = container_of(inode->i_cdev, struct DeviceCtx, cdev);
	struct AddressSpace *ctx = NULL;
	struct PageDir* pgd = NULL;
	dma_addr_t pgd_dma_addr = 0;
	int status = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ctx)) {
		status = -ENOMEM;
		cry(kzalloc, status);
		goto err;
	}

	pgd = dma_alloc_coherent(&device->pci_dev->dev, sizeof(*pgd), &pgd_dma_addr, GFP_KERNEL);
	if (IS_ERR_OR_NULL(pgd)) {
		status = -ENOMEM;
		cry(dma_alloc_coherent, status);
		goto err;
	}
	ctx->pgd = pgd;
	ctx->pgd_dma_addr = pgd_dma_addr;

	// DeviceCtx init safe part
	// TODO increment device refcount (?)
	ctx->device = device;
	file->private_data = ctx;
	INIT_LIST_HEAD(&ctx->areas);
	INIT_LIST_HEAD(&ctx->buffers);
	INIT_LIST_HEAD(&ctx->list_node);
	list_add(&ctx->list_node, &device->contexts);
	return nonseekable_open(inode, file);

err:
	if (ctx != NULL) {
		kfree(ctx);
	}
	if (pgd != NULL) {
		dma_free_coherent(&device->pci_dev->dev, sizeof(*pgd), pgd, pgd_dma_addr);
	}
	return status;

}

int ctx_release(struct inode *inode, struct file *file)
{
	// TODO cleanup
	return -EIO;
}

long ctx_ioctl_create_buffer(struct DeviceCtx* device, struct AddressSpace* ctx, struct udoomdev_ioctl_create_buffer* cmd)
{
	struct Buffer* buff = NULL;
	dma_addr_t dma_addr = {0};
	void* hst_addr = NULL;
	long status = 0;
	dbg("creating buffer\n");

	buff = kzalloc(sizeof(*buff), GFP_KERNEL);
	if (buff == NULL) {
		status = -ENOMEM;
		cry(kzalloc, status);
		goto err;
	}
	INIT_LIST_HEAD(&buff->list_node);
	
	// TODO handle larger allocations
	hst_addr = dma_alloc_coherent(&device->pci_dev->dev, cmd->size, &dma_addr, GFP_KERNEL);
	if (IS_ERR_OR_NULL(hst_addr)) {
		status = -ENOMEM;
		cry(dma_alloc_coherent, status);
		goto err;
	}

	buff->hst_addr = hst_addr;
	buff->dma_addr = dma_addr;
	buff->size = cmd->size;

	// Create fd for buffer, copying chardev file flags.
	status = anon_inode_getfd(THIS_MODULE->name, &buffer_api, buff, O_RDWR);
	if (IS_ERR_VALUE(status)) {
		cry(anon_inode_getfd, status);
		goto err;
	}

	BUG_ON(IS_ERR_VALUE(status));

	buff->ctx = ctx;
	list_add(&buff->list_node, &ctx->buffers);
	dbg("buffer created: %d\n", (int) status);
	return status;

err:
	if (buff != NULL) {
		kfree(buff);
	}
	return status;
}

long ctx_ioctl_map_buffer(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_map_buffer *cmd)
{
	struct fd fd = fdget(cmd->buf_fd);
	struct Buffer* buff = (fd.file == NULL) ? NULL : fd.file->private_data;
	long status = 0;
	
	if (buff == NULL) {
		status = -EBADF;
		goto err;
	}

	
err:
	return status;
}

long ctx_ioctl_unmap_buffer(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_unmap_buffer *cmd)
{
	return -EIO;
}

long ctx_ioctl_run(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_run *cmd)
{
	return -EIO;
}

long ctx_ioctl_wait(struct DeviceCtx *device, struct AddressSpace *ctx, struct udoomdev_ioctl_wait *cmd)
{
	return -EIO;
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

long ctx_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	struct AddressSpace *ctx = file->private_data;
	struct DeviceCtx *device = ctx->device;
	union {
		struct udoomdev_ioctl_create_buffer create;
		struct udoomdev_ioctl_map_buffer map;
		struct udoomdev_ioctl_unmap_buffer unmap;
		struct udoomdev_ioctl_run run;
		struct udoomdev_ioctl_wait wait;
	} data;

	// TODO make it compile
	int status = 0;
	switch (cmd) {
		case UDOOMDEV_IOCTL_CREATE_BUFFER: status = copy_from_user(&data.create, (void*) args, sizeof(data.create)); break;
		case UDOOMDEV_IOCTL_MAP_BUFFER:    status = copy_from_user(&data.map,    (void*) args, sizeof(data.map)); break;
		case UDOOMDEV_IOCTL_UNMAP_BUFFER:  status = copy_from_user(&data.unmap,  (void*) args, sizeof(data.unmap)); break;
		case UDOOMDEV_IOCTL_RUN:           status = copy_from_user(&data.run,    (void*) args, sizeof(data.run)); break;
		case UDOOMDEV_IOCTL_WAIT:          status = copy_from_user(&data.wait,   (void*) args, sizeof(data.wait)); break;
	}

	if (status > 0) {
		dbg("detected ioctl fault");
		return -EFAULT;
	}

	switch (cmd) {
		case UDOOMDEV_IOCTL_CREATE_BUFFER: return ctx_ioctl_create_buffer(device, ctx, &data.create);
		case UDOOMDEV_IOCTL_MAP_BUFFER:    return ctx_ioctl_map_buffer(device, ctx, &data.map);
		case UDOOMDEV_IOCTL_UNMAP_BUFFER:  return ctx_ioctl_unmap_buffer(device, ctx, &data.unmap);
		case UDOOMDEV_IOCTL_RUN:           return ctx_ioctl_run(device, ctx, &data.run);
		case UDOOMDEV_IOCTL_WAIT:          return ctx_ioctl_wait(device, ctx, &data.wait);
	}

	
	return -ENOTTY;
}

///////////////////////////////////////////////////////////////////////////////
// Buffer interface

int buffer_release(struct inode* inode, struct file* filp)
{
	return -EIO;
}

int buffer_mmap(struct file* filp, struct vm_area_struct* vma)
{
	dbg("mmap start\n");
	vma->vm_ops = &buffer_vm_api;
	dbg("mmap end\n");
	return 0; 
}

// TODO: dlaczego osobno alokowac kazda strone?

vm_fault_t buffer_host_fault(struct vm_fault *vmf)
{
	struct file* filp = vmf->vma->vm_file;
	struct Buffer* buff = filp->private_data;
	struct page* page = NULL;

    // zweryfikować, że pgoff mieści się w rozmiarze bufora (jeśli nie, zwrócić VM_FAULT_SIGBUS)
	if (vmf->pgoff != 0) {
		dbg("buffer_host_fault: pgoff >= buff->size\n");
		
		return VM_FAULT_SIGBUS;
	}

    // wziąć adres wirtualny (w jądrze) odpowiedniej strony bufora i przekształcić go przez virt_to_page na struct page *
	page = virt_to_page(buff->hst_addr);

	// zwiększyć licznik referencji do tej strony (get_page)
	get_page(page);
    
	// wstawić wskaźnik na tą strukturę do otrzymanej struktury vm_fault (pole page)
	vmf->page = page;
    // zwrócić 0
	
	dbg("buffer fault\n");
	return 0;

}

///////////////////////////////////////////////////////////////////////////////
// Integration

MODULE_LICENSE("GPL");
module_init(drv_initialize);
module_exit(drv_terminate);

///////////////////////////////////////////////////////////////////////////////
// Debug

void dev_printk_status(struct DeviceCtx* device)
{
	static uint32_t stats[UHARDDOOM_STATS_NUM];
	uint32_t status;
	size_t idx;

	dbg("reading state..\n");

	status = R(UHARDDOOM_STATUS);
	for (idx = 0; idx < UHARDDOOM_STATS_NUM; ++idx) {
		stats[idx] = R(UHARDDOOM_STATS(idx));
	}

	dbg("UHARDDOOM_STATUS_BATCH: %u\n", (status & UHARDDOOM_STATUS_BATCH));
	dbg("UHARDDOOM_STATUS_JOB: %u\n", (status & UHARDDOOM_STATUS_JOB));
	dbg("UHARDDOOM_STATUS_CMD: %u\n", (status & UHARDDOOM_STATUS_CMD));
	dbg("UHARDDOOM_STATUS_FE: %u\n", (status & UHARDDOOM_STATUS_FE));
	dbg("UHARDDOOM_STATUS_SRD: %u\n", (status & UHARDDOOM_STATUS_SRD));
	dbg("UHARDDOOM_STATUS_SPAN: %u\n", (status & UHARDDOOM_STATUS_SPAN));
	dbg("UHARDDOOM_STATUS_COL: %u\n", (status & UHARDDOOM_STATUS_COL));
	dbg("UHARDDOOM_STATUS_FX: %u\n", (status & UHARDDOOM_STATUS_FX));
	dbg("UHARDDOOM_STATUS_SWR: %u\n", (status & UHARDDOOM_STATUS_SWR));
	// dbg("UHARDDOOM_STATUS_FIFO_SRDCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SRDCMD));
	// dbg("UHARDDOOM_STATUS_FIFO_SPANCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANCMD));
	// dbg("UHARDDOOM_STATUS_FIFO_COLCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLCMD));
	// dbg("UHARDDOOM_STATUS_FIFO_FXCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXCMD));
	// dbg("UHARDDOOM_STATUS_FIFO_SWRCMD: %u\n", (status & UHARDDOOM_STATUS_FIFO_SWRCMD));
	// dbg("UHARDDOOM_STATUS_FIFO_COLIN: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLIN));
	// dbg("UHARDDOOM_STATUS_FIFO_FXIN: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXIN));
	// dbg("UHARDDOOM_STATUS_FIFO_FESEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_FESEM));
	// dbg("UHARDDOOM_STATUS_FIFO_SRDSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_SRDSEM));
	// dbg("UHARDDOOM_STATUS_FIFO_COLSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLSEM));
	// dbg("UHARDDOOM_STATUS_FIFO_SPANSEM: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANSEM));
	// dbg("UHARDDOOM_STATUS_FIFO_SPANOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_SPANOUT));
	// dbg("UHARDDOOM_STATUS_FIFO_COLOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_COLOUT));
	// dbg("UHARDDOOM_STATUS_FIFO_FXOUT: %u\n", (status & UHARDDOOM_STATUS_FIFO_FXOUT));

	// dbg("UHARDDOOM_STAT_FW_JOB: %u\n", stats[0x00]);
	// dbg("UHARDDOOM_STAT_FW_CMD: %u\n", stats[0x01]);
	// dbg("UHARDDOOM_STAT_CMD_BLOCK: %u\n", stats[0x56]);
	// dbg("UHARDDOOM_STAT_CMD_WORD: %u\n", stats[0x57]);
	// dbg("UHARDDOOM_STAT_FE_INSN: %u\n", stats[0x58]);
	// dbg("UHARDDOOM_STAT_FE_LOAD: %u\n", stats[0x59]);
	// dbg("UHARDDOOM_STAT_FE_STORE: %u\n", stats[0x5a]);
	// dbg("UHARDDOOM_STAT_MMIO_READ: %u\n", stats[0x5c]);
	// dbg("UHARDDOOM_STAT_MMIO_WRITE: %u\n", stats[0x5d]);
	// dbg("UHARDDOOM_STAT_SRD_CMD: %u\n", stats[0x60]);
	// dbg("UHARDDOOM_STAT_SRD_READ: %u\n", stats[0x61]);
	// dbg("UHARDDOOM_STAT_SRD_BLOCK: %u\n", stats[0x62]);
	// dbg("UHARDDOOM_STAT_SRD_FESEM: %u\n", stats[0x63]);
	// dbg("UHARDDOOM_STAT_SWR_CMD: %u\n", stats[0x78]);
	// dbg("UHARDDOOM_STAT_SWR_DRAW: %u\n", stats[0x79]);
	// dbg("UHARDDOOM_STAT_SWR_BLOCK: %u\n", stats[0x7a]);
	// dbg("UHARDDOOM_STAT_SWR_BLOCK_READ: %u\n", stats[0x7b]);
	// dbg("UHARDDOOM_STAT_SWR_BLOCK_TRANS: %u\n", stats[0x7c]);
	// dbg("UHARDDOOM_STAT_SWR_SRDSEM: %u\n", stats[0x7d]);
	// dbg("UHARDDOOM_STAT_SWR_COLSEM: %u\n", stats[0x7e]);
	// dbg("UHARDDOOM_STAT_SWR_SPANSEM: %u\n", stats[0x7f]);

}
