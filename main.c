// main.c - Menu de acesso + GPIO + usuários em um único arquivo.
// Compile: gcc -O2 -Wall -o acesso main.c -lcrypt
// Rode   : sudo ./acesso

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
#include <ctype.h>
#include <crypt.h>
#include <termios.h>
#include <limits.h>

// -------------------- Configuração de GPIO (BCM) --------------------
#define DOOR1_BCM 17
#define DOOR2_BCM 27

// -------------------- Arquivos de persistência ----------------------
#ifndef USERS_DB_DEFAULT
#define USERS_DB_DEFAULT "/etc/acesso/users.db"
#endif

#ifndef EVENTS_LOG_FILE
#define EVENTS_LOG_FILE  "/var/log/acesso_events.log"
#endif

// -------------------- Usuários --------------------------------------
typedef enum { ROLE_USER = 0, ROLE_ADMIN = 1 } Role;

typedef struct {
    char name[64];
    Role role;
    char hash[128]; // crypt $6$... (SHA-512)
} User;

#define MAX_USERS 256
static User g_users[MAX_USERS];
static int  g_user_n = 0;
static char g_users_db_path[256] = {0};

// -------------------- Eventos ---------------------------------------
typedef struct {
    time_t ts;
    char   user[64];
    int    door;      // 1 ou 2
    char   action[16];// "OPEN" | "CLOSE"
} Event;

#define MAX_EVENTS 1024
static Event g_events[MAX_EVENTS];
static int   g_evt_n = 0;

// -------------------- Util de arquivo simples -----------------------
static int write_str(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t r = write(fd, val, strlen(val));
    int e = errno;
    close(fd);
    if (r < 0) { errno = e; return -1; }
    return 0;
}

static int append_line(const char *path, const char *line) {
    int fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd < 0) return -1;
    ssize_t r = write(fd, line, strlen(line));
    int e = errno;
    close(fd);
    if (r < 0) { errno = e; return -1; }
    return 0;
}

static int ensure_dir(const char *p) {
    // cria diretório pai do caminho, se necessário
    char tmp[256]; strncpy(tmp, p, sizeof tmp - 1);
    char *slash = strrchr(tmp, '/');
    if (!slash) return 0;
    *slash = 0;
    struct stat st;
    if (stat(tmp, &st) == 0) return 0;
    if (mkdir(tmp, 0755) == 0 || errno == EEXIST) return 0;
    return -1;
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

// -------------------- GPIO via sysfs (com base dinâmica) ------------
static int sysfs_base = -1;

static int detect_sysfs_base(void) {
    const char *root = "/sys/class/gpio";
    DIR *d = opendir(root);
    if (!d) return -1;

    int best_base = -1;
    int best_ngpio = -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "gpiochip", 8) != 0) continue;

        char p_base[PATH_MAX], p_ngpio[PATH_MAX];
        int n1 = snprintf(p_base, sizeof p_base, "%s/%s/base", root, de->d_name);
        int n2 = snprintf(p_ngpio, sizeof p_ngpio, "%s/%s/ngpio", root, de->d_name);
        if (n1 < 0 || n1 >= (int)sizeof p_base) continue;
        if (n2 < 0 || n2 >= (int)sizeof p_ngpio) continue;

        int base  = read_int_file(p_base);
        int ngpio = read_int_file(p_ngpio);
        if (base < 0 || ngpio < 0) continue;

        // chip "principal" do Pi costuma ter >=54 linhas
        if (ngpio >= 54 && ngpio > best_ngpio) {
            best_ngpio = ngpio;
            best_base  = base;
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

static int bcm_to_sysfs(int bcm) {
    int base = ensure_sysfs_base();
    if (base < 0) return -1;
    return base + bcm;
}

static int gpio_export_global(int global_gpio) {
    char gp[256];
    snprintf(gp, sizeof gp, "/sys/class/gpio/gpio%d", global_gpio);
    if (file_exists(gp)) return 0;
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
    return write_str(p, dir); // "out" ou "in"
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

// -------------------- Util geral ------------------------------------
static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void trim(char *s){
    if(!s) return;
    size_t n = strlen(s);
    while(n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) s[--n]=0;
    while(*s==' '||*s=='\t') memmove(s,s+1,strlen(s));
}

static int prompt_password(const char *msg, char *out, size_t n, int confirm){
    struct termios oldt, newt;
    bool have_tty = isatty(STDIN_FILENO);
    int echo_disabled = 0;

    // mostra o prompt no stderr (menos bufferizado)
    fprintf(stderr, "%s", msg);
    fflush(stderr);

    if (have_tty && tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) == 0) {
            echo_disabled = 1;
        }
    }

    if (!fgets(out, (int)n, stdin)) {
        out[0] = 0;
    } else {
        // tira \n e espaços
        size_t L = strlen(out);
        while (L && (out[L-1]=='\n' || out[L-1]=='\r' || out[L-1]==' ' || out[L-1]=='\t')) out[--L] = 0;
    }

    if (echo_disabled) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fprintf(stderr, "\n"); // quebra linha após a senha

    if (confirm) {
        char again[128] = {0};

        fprintf(stderr, "Confirme: ");
        fflush(stderr);

        echo_disabled = 0;
        if (have_tty && tcgetattr(STDIN_FILENO, &oldt) == 0) {
            newt = oldt; newt.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) == 0) echo_disabled = 1;
        }

        if (!fgets(again, (int)sizeof again, stdin)) {
            if (echo_disabled) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            fprintf(stderr, "\n");
            return -1;
        }
        size_t L = strlen(again);
        while (L && (again[L-1]=='\n' || again[L-1]=='\r' || again[L-1]==' ' || again[L-1]=='\t')) again[--L] = 0;

        if (echo_disabled) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fprintf(stderr, "\n");

        return strcmp(out, again) == 0 ? 0 : -1;
    }

    return 0;
}

// -------------------- DB de usuários --------------------------------
static const char* role_str(Role r){ return r==ROLE_ADMIN?"ADMIN":"USER"; }

static int is_valid_username(const char *name){
    if(!name || !*name) return 0;
    size_t n = strlen(name);
    if(n<1 || n>63) return 0;
    for(size_t i=0;i<n;i++){
        if(!(isalnum((unsigned char)name[i]) || name[i]=='_' || name[i]=='-' || name[i]=='.'))
            return 0;
    }
    return 1;
}

static int find_user(const char *name){
    for(int i=0;i<g_user_n;i++){
        if(strcmp(g_users[i].name,name)==0) return i;
    }
    return -1;
}

static int gen_salt(char *out, size_t n){
    static const char tbl[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    if(n<4+1+16+1) return -1; // "$6$" + salt + "$"
    unsigned char buf[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd<0 || read(fd,buf,sizeof buf)!=sizeof buf){ if(fd>=0) close(fd); return -1; }
    if(fd>=0) close(fd);
    char salt[20]={0};
    for(int i=0;i<16;i++) salt[i]=tbl[buf[i] % (sizeof(tbl)-1)];
    snprintf(out,n,"$6$%s$",salt);
    return 0;
}

static int hash_password(const char *password, char *out, size_t n){
    struct crypt_data cd; memset(&cd,0,sizeof cd);
    char salt[64];
    if(gen_salt(salt,sizeof salt)<0) return -1;
    char *h = crypt_r(password, salt, &cd);
    if(!h || strlen(h)>=n) return -1;
    strcpy(out,h);
    return 0;
}

static int verify_password(const char *password, const char *stored_hash){
    struct crypt_data cd; memset(&cd,0,sizeof cd);
    char *h = crypt_r(password, stored_hash, &cd);
    if(!h) return 0;
    return (strcmp(h, stored_hash)==0);
}

static int save_users_db(const char *path){
    ensure_dir(path);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0640);
    if(fd<0) return -1;
    for(int i=0;i<g_user_n;i++){
        dprintf(fd, "%s:%s:%s\n",
            g_users[i].name,
            role_str(g_users[i].role),
            g_users[i].hash);
    }
    close(fd);
    return 0;
}

static int load_users_db(const char *path){
    FILE *f = fopen(path,"r");
    if(!f) return -1;
    char line[512];
    while(fgets(line,sizeof line,f)){
        char name[64]={0}, roleb[16]={0}, hash[128]={0};
        char *p=line; size_t i=0;
        while(*p && *p!=':' && i<sizeof(name)-1) name[i++]=*p++;
        if(*p!=':') continue; p++;
        i=0; while(*p && *p!=':' && i<sizeof(roleb)-1) roleb[i++]=*p++;
        if(*p!=':') continue; p++;
        i=0; while(*p && *p!='\n' && i<sizeof(hash)-1) hash[i++]=*p++;
        if(!is_valid_username(name)) continue;
        Role r = (strcasecmp(roleb,"admin")==0)?ROLE_ADMIN:ROLE_USER;
        if(g_user_n<MAX_USERS){
            strncpy(g_users[g_user_n].name,name,sizeof g_users[g_user_n].name-1);
            g_users[g_user_n].role=r;
            strncpy(g_users[g_user_n].hash,hash,sizeof g_users[g_user_n].hash-1);
            g_user_n++;
        }
    }
    fclose(f);
    return 0;
}

static int users_init(const char *path){
    const char *use = (path && *path)? path : USERS_DB_DEFAULT;
    strncpy(g_users_db_path, use, sizeof g_users_db_path - 1);
    if(load_users_db(use)<0){
        // cria vazio
        return save_users_db(use);
    }
    return 0;
}

static int users_add(const char *name, Role role, const char *password){
    if(!is_valid_username(name)) return -1;
    if(find_user(name)>=0) return -2;
    if(g_user_n>=MAX_USERS) return -1;

    char hash[128];
    if(hash_password(password,hash,sizeof hash)<0) return -1;

    strncpy(g_users[g_user_n].name,name,sizeof g_users[g_user_n].name-1);
    g_users[g_user_n].role=role;
    strncpy(g_users[g_user_n].hash,hash,sizeof g_users[g_user_n].hash-1);
    g_user_n++;
    return save_users_db(g_users_db_path);
}

static int users_auth(const char *name, const char *password, Role *out_role){
    int idx = find_user(name);
    if(idx<0) return 0;
    if(!verify_password(password, g_users[idx].hash)) return 0;
    if(out_role) *out_role = g_users[idx].role;
    return 1;
}

// -------------------- Eventos ---------------------------------------
static void event_append(const char *user, int door, const char *action){
    if(g_evt_n < MAX_EVENTS){
        g_events[g_evt_n].ts = time(NULL);
        strncpy(g_events[g_evt_n].user, user?user:"-", sizeof g_events[g_evt_n].user - 1);
        g_events[g_evt_n].door = door;
        strncpy(g_events[g_evt_n].action, action, sizeof g_events[g_evt_n].action - 1);
        g_evt_n++;
    }
    // também persiste em arquivo
    char line[256];
    struct tm tm; time_t now = time(NULL); localtime_r(&now,&tm);
    strftime(line, sizeof line, "%Y-%m-%d %H:%M:%S", &tm);
    char buf[320];
    snprintf(buf, sizeof buf, "%s user=%s door=%d action=%s\n", line, user?user:"-", door, action);
    ensure_dir(EVENTS_LOG_FILE);
    append_line(EVENTS_LOG_FILE, buf);
}

static void events_print_all(void){
    for(int i=0;i<g_evt_n;i++){
        char ts[64];
        struct tm tm; localtime_r(&g_events[i].ts, &tm);
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
        printf("%s  user=%s  door=%d  action=%s\n",
               ts, g_events[i].user, g_events[i].door, g_events[i].action);
    }
}

// -------------------- Fluxos de porta --------------------------------
static int door_global_from_num(int door){
    int bcm = (door==1)?DOOR1_BCM:DOOR2_BCM;
    return bcm_to_sysfs(bcm);
}

static void door_init_outputs(void){
    int g1 = door_global_from_num(1);
    int g2 = door_global_from_num(2);
    if (g1<0 || g2<0) { fprintf(stderr,"[ERR] sysfs base invalida\n"); exit(1); }
    gpio_export_global(g1);
    gpio_export_global(g2);
    gpio_set_dir_global(g1,"out");
    gpio_set_dir_global(g2,"out");
    gpio_write_global(g1,0);
    gpio_write_global(g2,0);
}

static int auth_prompt(Role *out_role, char *out_user, size_t nuser){
    char user[64]={0}, pwd[128]={0};
    printf("Usuario: "); fflush(stdout);
    if(!fgets(user,sizeof user, stdin)) return 0;
    trim(user);
    if(prompt_password("Senha: ", pwd, sizeof pwd, 0)<0) return 0;
    Role r=ROLE_USER;
    if(!users_auth(user,pwd,&r)) return 0;
    if(out_role) *out_role = r;
    if(out_user){ strncpy(out_user,user,nuser-1); out_user[nuser-1]=0; }
    return 1;
}

static void open_door_flow(int door){
    char user[64]={0};
    Role r=ROLE_USER;
    if(!auth_prompt(&r,user,sizeof user)){
        printf("Autenticacao falhou.\n");
        return;
    }
    int g = door_global_from_num(door);
    if(g<0){ printf("GPIO invalido\n"); return; }

    // Abrir
    gpio_write_global(g,1);
    printf(">>> Porta %d ABERTA por %s (role=%s)\n", door, user, role_str(r));
    event_append(user, door, "OPEN");

    // Timeout 5s (por enquanto sem botão)
    for(int i=0;i<5;i++){ msleep(1000); }

    // Fechar
    gpio_write_global(g,0);
    printf("<<< Porta %d FECHADA (timeout)\n", door);
    event_append(user, door, "CLOSE");
}

// -------------------- Menu -------------------------------------------
static void print_menu(void){
    printf("\n=== GERENCIAMENTO DE ACESSO ===\n");
    printf("1) Cadastrar usuario\n");
    printf("2) Listar usuarios (ADMIN)\n");
    printf("3) Testar login (auth)\n");
    printf("4) Abrir Porta 1\n");
    printf("5) Abrir Porta 2\n");
    printf("6) Listar eventos (ADMIN)\n");
    printf("0) Sair\n");
    printf("> ");
    fflush(stdout);
}

static void menu_loop(void){
    char opt[32];
    for(;;){
        print_menu();
        if(!fgets(opt,sizeof opt,stdin)) break;
        trim(opt);
        if(strcmp(opt,"0")==0) break;

        if(strcmp(opt,"1")==0){
            char name[64]={0}, roleb[16]={0}, pwd[128]={0};
            printf("Nome (a-zA-Z0-9_-.): "); fflush(stdout);
            if(!fgets(name,sizeof name,stdin)) continue; trim(name);
            printf("Role (admin|user): "); fflush(stdout);
            if(!fgets(roleb,sizeof roleb,stdin)) continue; trim(roleb);
            int is_admin = (strcasecmp(roleb,"admin")==0);
            if(!is_valid_username(name)){ printf("Nome invalido.\n"); continue; }
            if(prompt_password("Senha: ", pwd, sizeof pwd, 1)<0){
                printf("Senhas nao conferem.\n"); continue;
            }
            int rc = users_add(name, is_admin?ROLE_ADMIN:ROLE_USER, pwd);
            if(rc==0)       printf("Usuario '%s' criado (%s).\n", name, roleb);
            else if(rc==-2) printf("Usuario ja existe.\n");
            else            printf("Falha ao criar usuario.\n");
        }
        else if(strcmp(opt,"2")==0){
            // exige admin
            Role r=ROLE_USER; char who[64]={0};
            if(!auth_prompt(&r,who,sizeof who) || r!=ROLE_ADMIN){
                printf("Acesso negado.\n"); continue;
            }
            printf("== Usuarios ==\n");
            for(int i=0;i<g_user_n;i++){
                printf("- %s [%s]\n", g_users[i].name, role_str(g_users[i].role));
            }
        }
        else if(strcmp(opt,"3")==0){
            Role r=ROLE_USER; char who[64]={0};
            if(auth_prompt(&r,who,sizeof who))
                printf("OK (%s)\n", role_str(r));
            else
                printf("FAIL\n");
        }
        else if(strcmp(opt,"4")==0){
            open_door_flow(1);
        }
        else if(strcmp(opt,"5")==0){
            open_door_flow(2);
        }
        else if(strcmp(opt,"6")==0){
            // exige admin
            Role r=ROLE_USER; char who[64]={0};
            if(!auth_prompt(&r,who,sizeof who) || r!=ROLE_ADMIN){
                printf("Acesso negado.\n"); continue;
            }
            printf("== Eventos ==\n");
            events_print_all();
            printf("(arquivo: %s)\n", EVENTS_LOG_FILE);
        }
        else {
            printf("Opcao invalida.\n");
        }
    }
}

// -------------------- main -------------------------------------------
int main(void){

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (getuid()!=0){
        fprintf(stderr, "Este programa deve rodar como root (sudo).\n");
        return 1;
    }

    // prepara DB de usuários
    if (users_init(NULL) < 0) {
        fprintf(stderr, "Nao foi possivel inicializar DB de usuarios (%s).\n", USERS_DB_DEFAULT);
        return 1;
    }

    // prepara GPIO das portas
    if (ensure_sysfs_base() < 0) {
        fprintf(stderr, "Falha ao detectar base do sysfs GPIO. Verifique /sys/class/gpio.\n");
        return 1;
    }
    door_init_outputs();

    // entra no menu
    menu_loop();

    // opcional: deixar pinos em 0 e desexportar ao sair
    int g1 = bcm_to_sysfs(DOOR1_BCM);
    int g2 = bcm_to_sysfs(DOOR2_BCM);
    gpio_write_global(g1,0);
    gpio_write_global(g2,0);
    // gpio_unexport_global(g1); gpio_unexport_global(g2);

    return 0;
}
