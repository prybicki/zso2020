#include <linux/printk.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/types.h>
#include <linux/slab.h>

#include <linux/cdev.h>

#include "uharddoom.h"


///////////////////////////////////////////////////////////////////////////////
// Callable

#define dbg(fmt, ...) printk(KERN_NOTICE "uharddoom: [%d] " fmt, __LINE__, ##__VA_ARGS__)
#define cry(fn, value) dbg("%s(...) failed with %d\n", #fn, value)

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
int dev_init_hardware(struct DeviceCtx* device);
int dev_init_chardev(struct DeviceCtx* device);

int  file_open(struct inode *, struct file *);
long file_unlocked_ioctl(struct file *, unsigned int, unsigned long);
long file_compat_ioctl(struct file *, unsigned int, unsigned long);
int  file_mmap(struct file *, struct vm_area_struct *);
int  file_release(struct inode *, struct file *);


///////////////////////////////////////////////////////////////////////////////
// Structs

struct DeviceCtx {
	struct cdev cdev;
	struct device* sysfs;
	struct pci_dev* pci_dev;
	void __iomem* iomem;
	size_t index;

	bool pci_enable_device_done;
	bool pci_request_regions_done;
	// pci_iomap_done == iomem;

	bool cdev_add_done;
	// device_create_done == sysfs;
};

///////////////////////////////////////////////////////////////////////////////
// Constants

#define MAX_DEVICE_COUNT 256
#define DRIVER_NAME "uharddoom"

const struct pci_device_id known_devices[] = {
	{PCI_DEVICE(UHARDDOOM_VENDOR_ID, UHARDDOOM_DEVICE_ID)}, 
	{0}
};

// TODO: Does it matter? How?
struct class device_class = {
	.name = "uharddoomclass",
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

struct file_operations file_api = {
	.owner = THIS_MODULE,
	.open           = file_open,
	.mmap           = file_mmap,
	.release        = file_release,
	.compat_ioctl   = file_compat_ioctl,
	.unlocked_ioctl = file_unlocked_ioctl,
};

///////////////////////////////////////////////////////////////////////////////
// Globals

dev_t dev_major;
bool pci_register_driver_done;
bool class_register_done;

struct mutex devices_mutex;
struct DeviceCtx* devices[MAX_DEVICE_COUNT];

///////////////////////////////////////////////////////////////////////////////
// Driver code

int drv_initialize(void)
{
	int error = 0;

	dbg("initialization started, build %s %s\n", __DATE__, __TIME__);

	error = alloc_chrdev_region(&dev_major, 0, MAX_DEVICE_COUNT, DRIVER_NAME);
	if (error) {
		cry(alloc_chrdev_region, error);
		goto failed;
	}

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
	BUG_ON(error);
	return error;

failed:
	drv_terminate();
	return error;
}

void drv_terminate(void)
{
	dbg("termination started\n");

	// if (pci_register_driver_done) {
	// 	pci_unregister_driver(&driver_api);
	// 	pci_register_driver_done = false;
	// }

	// if (class_register_done) {
	// 	class_unregister(&device_class);
	// 	class_register_done = false;
	// }

	// if (dev_major) {
	// 	unregister_chrdev_region(dev_major, MAX_DEVICE_COUNT);
	// 	dev_major = 0;
	// }

	dbg("termination done\n");
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
		goto out;
	}

	status = kzalloc(sizeof(struct DeviceCtx), GFP_KERNEL);
	if (status == NULL) {
		status = ERR_PTR(-ENOMEM);
		goto out;
	}
	devices[idx] = status;
	devices[idx]->index = idx;
	devices[idx]->pci_dev = pci_dev;
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
	if (IS_ERR(iomem)) {
		error = PTR_ERR(iomem);
		cry(pci_iomap, error);
		goto out;
	}
	device->iomem = iomem;

out:
	return error;
}

int dev_init_chardev(struct DeviceCtx* device)
{
	struct device* sysfs = NULL;
	dev_t dev_idx = 0;
	int error = 0;

	dev_idx = MKDEV(dev_major, device->index),
	cdev_init(&device->cdev, &file_api);
	device->cdev.owner = THIS_MODULE;

	error = cdev_add(&device->cdev, dev_idx, 1);
	if (error) {
		cry(cdev_add, error);
		goto out;
	}
	device->cdev_add_done = true;

	sysfs = device_create(&device_class, &device->pci_dev->dev, dev_idx, NULL, "udoom%zd", device->index);
	if (IS_ERR(sysfs)) {
		error = PTR_ERR(sysfs);
		cry(device_create, error);
		goto out;
	}
	device->sysfs = sysfs;

out:
	return error;
}

// Always called from process context, so it can sleep.
int dev_probe(struct pci_dev* pci_dev, const struct pci_device_id *id)
{
	struct DeviceCtx* device = NULL;
	int error = 0;
	
	dbg("probe started\n");

	device = dev_alloc(pci_dev);
	if (IS_ERR(device)) {
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

	dbg("probe done [%zd]\n", device->index);

fail:
	// TODO!
	return error;
}


void dev_remove(struct pci_dev *dev)
{
	// cdev_del
	// device_destroy
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
// File code

int file_open(struct inode *inode, struct file *file)
{
	return -EIO;
}

long file_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	return -EIO;
}

long file_compat_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	return -EIO;
}

int file_mmap(struct file *file, struct vm_area_struct *vm)
{
	return -EIO;
}

int file_release(struct inode *inode, struct file *file)
{
	return -EIO;
}

///////////////////////////////////////////////////////////////////////////////
// Integration

MODULE_LICENSE("GPL");
module_init(drv_initialize);
module_exit(drv_terminate);
