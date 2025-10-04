// main.c

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>

#define DOOR1_BCM 17   
#define DOOR2_BCM 27

static int sysfs_base = -1; // detectado em runtime

// ---------- util de arquivo ----------
static int write_str(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t r = write(fd, val, strlen(val));
    int e = errno;
    close(fd);
    if (r < 0) { errno = e; return -1; }
    return 0;
}

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int read_int_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[64] = {0};
    int n = read(fd, buf, sizeof(buf) - 1);
    int e = errno;
    close(fd);
    if (n <= 0) { errno = e; return -1; }
    return atoi(buf);
}

// ---------- detecção da base sysfs ----------
static int detect_sysfs_base(void) {
    const char *root = "/sys/class/gpio";
    DIR *d = opendir(root);
    if (!d) return -1;

    int best_base = -1;
    int best_ngpio = -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "gpiochip", 8) != 0) continue;

        char p_base[256], p_ngpio[256];
        snprintf(p_base, sizeof p_base, "%s/%s/base", root, de->d_name);
        snprintf(p_ngpio, sizeof p_ngpio, "%s/%s/ngpio", root, de->d_name);

        int base = read_int_file(p_base);
        int ngpio = read_int_file(p_ngpio);
        if (base < 0 || ngpio < 0) continue;

        if (ngpio >= 54 && ngpio > best_ngpio) {
            best_ngpio = ngpio;
            best_base = base;
        }
    }
    closedir(d);

    if (best_base < 0) {
        int maybe = read_int_file("/sys/class/gpio/gpiochip0/base");
        if (maybe >= 0) best_base = maybe;
    }
    return best_base;
}

static int ensure_sysfs_base(void) {
    if (sysfs_base >= 0) return sysfs_base;
    sysfs_base = detect_sysfs_base();
    return sysfs_base;
}

// ---------- mapeamento BCM -> global sysfs ----------
static int bcm_to_sysfs(int bcm) {
    int base = ensure_sysfs_base();
    if (base < 0) return -1;
    return base + bcm;
}

// ---------- helpers GPIO sysfs ----------
static int gpio_export_global(int global_gpio) {
    char gp[128];
    snprintf(gp, sizeof gp, "/sys/class/gpio/gpio%d", global_gpio);
    if (file_exists(gp)) return 0; // já exportado
    char buf[16]; snprintf(buf, sizeof buf, "%d", global_gpio);
    if (write_str("/sys/class/gpio/export", buf) < 0) {

        if (errno == EBUSY) return 0;
        return -1;
    }
    return 0;
}

static int gpio_unexport_global(int global_gpio) {
    char buf[16]; snprintf(buf, sizeof buf, "%d", global_gpio);
    if (write_str("/sys/class/gpio/unexport", buf) < 0) {

        if (errno == ENOENT) return 0;
        return -1;
    }
    return 0;
}

static int gpio_set_dir_global(int global_gpio, const char *dir) {
    char p[256]; snprintf(p, sizeof p, "/sys/class/gpio/gpio%d/direction", global_gpio);
    return write_str(p, dir); 
}

static int gpio_write_global(int global_gpio, int value) {
    char p[256]; snprintf(p, sizeof p, "/sys/class/gpio/gpio%d/value", global_gpio);
    return write_str(p, value ? "1" : "0");
}

static int gpio_read_global(int global_gpio) {
    char p[256]; snprintf(p, sizeof p, "/sys/class/gpio/gpio%d/value", global_gpio);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    char c;
    ssize_t r = read(fd, &c, 1);
    int e = errno;
    close(fd);
    if (r != 1) { errno = e; return -1; }
    return (c == '1') ? 1 : 0;
}

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int door_bcm_to_global(int door) {
    int bcm = (door == 1) ? DOOR1_BCM : DOOR2_BCM;
    return bcm_to_sysfs(bcm);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso (root):\n"
        "  %s --init\n"
        "  %s --on <porta 1|2>\n"
        "  %s --off <porta 1|2>\n"
        "  %s --blink <porta 1|2> <vezes> [intervalo_ms]\n"
        "  %s --read\n"
        "  %s --cleanup\n", prog, prog, prog, prog, prog, prog);
}

// ---------- main ----------
int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    // Garante que temos uma base válida
    if (ensure_sysfs_base() < 0) {
        fprintf(stderr, "Falha ao detectar base do sysfs GPIO. Verifique /sys/class/gpio.\n");
        return 1;
    }

    if (strcmp(argv[1], "--init") == 0) {
        int g1 = bcm_to_sysfs(DOOR1_BCM);
        int g2 = bcm_to_sysfs(DOOR2_BCM);
        if (g1 < 0 || g2 < 0) { fprintf(stderr, "BCM->sysfs falhou\n"); return 1; }

        if (gpio_export_global(g1) < 0 || gpio_export_global(g2) < 0) {
            perror("export");
            return 1;
        }
        if (gpio_set_dir_global(g1, "out") < 0 || gpio_set_dir_global(g2, "out") < 0) {
            perror("direction");
            return 1;
        }
        gpio_write_global(g1, 0);
        gpio_write_global(g2, 0);

        printf("Init OK:  | P1=%d, P2=%d (saida=0)\n",
                DOOR1_BCM, DOOR2_BCM);
        return 0;
    }

    if (strcmp(argv[1], "--on") == 0 && argc >= 3) {
        int door = atoi(argv[2]);
        if (door != 1 && door != 2) { usage(argv[0]); return 1; }
        int g = door_bcm_to_global(door);
        if (g < 0) { fprintf(stderr, "mapa BCM->sysfs falhou\n"); return 1; }
        if (gpio_write_global(g, 1) < 0) { perror("write"); return 1; }
        printf("Porta %d = ON (global %d)\n", door, g);
        return 0;
    }

    if (strcmp(argv[1], "--off") == 0 && argc >= 3) {
        int door = atoi(argv[2]);
        if (door != 1 && door != 2) { usage(argv[0]); return 1; }
        int g = door_bcm_to_global(door);
        if (g < 0) { fprintf(stderr, "mapa BCM->sysfs falhou\n"); return 1; }
        if (gpio_write_global(g, 0) < 0) { perror("write"); return 1; }
        printf("Porta %d = OFF (global %d)\n", door, g);
        return 0;
    }

    if (strcmp(argv[1], "--blink") == 0 && argc >= 4) {
        int door = atoi(argv[2]);
        int times = atoi(argv[3]);
        int interval = (argc >= 5) ? atoi(argv[4]) : 300; // ms
        if ((door != 1 && door != 2) || times <= 0) { usage(argv[0]); return 1; }
        int g = door_bcm_to_global(door);
        if (g < 0) { fprintf(stderr, "mapa BCM->sysfs falhou\n"); return 1; }

        for (int i = 0; i < times; i++) {
            gpio_write_global(g, 1);
            msleep(interval);
            gpio_write_global(g, 0);
            msleep(interval);
        }
        printf("Blink porta %d (%d vezes, %d ms) [global %d]\n", door, times, interval, g);
        return 0;
    }

    if (strcmp(argv[1], "--read") == 0) {
        int g1 = bcm_to_sysfs(DOOR1_BCM);
        int g2 = bcm_to_sysfs(DOOR2_BCM);
        int v1 = gpio_read_global(g1);
        int v2 = gpio_read_global(g2);
        if (v1 < 0 || v2 < 0) { perror("read"); return 1; }
        printf("P1(%d)=%d  P2(%d)=%d \n",
               DOOR1_BCM, v1, DOOR2_BCM, v2);
        return 0;
    }

    if (strcmp(argv[1], "--cleanup") == 0) {
        int g1 = bcm_to_sysfs(DOOR1_BCM);
        int g2 = bcm_to_sysfs(DOOR2_BCM);
        gpio_unexport_global(g1);
        gpio_unexport_global(g2);
        printf("Cleanup OK (unexport g1=%d g2=%d)\n", g1, g2);
        return 0;
    }

    usage(argv[0]);
    return 1;
}
