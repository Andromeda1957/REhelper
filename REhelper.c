#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define MAX 0xFF

void reverse(char *string){
    char output[MAX];
    int length = strnlen(string, MAX) - 1;

    for(int i = 0; i <= length; i++){
        output[i] = string[length - i];
    }

    printf("%s\n", output);
}

void pattern(char *string, int value){
    for(int i = 0; i < value; i++){
        printf("%s", string);
    }

    printf("\n");
}

void dump_stack(char *string){
    char stack[MAX] = "cat /proc/";

    strncat(stack, string, MAX);
    strncat(stack, "/stack", MAX);
    system(stack);
}

void dump_status(char *string){
    char status[MAX] = "cat /proc/";

    strncat(status, string, MAX);
    strncat(status, "/status", MAX);
    system(status);
}

void dump_io(char *string){
    char io[MAX] = "cat /proc/";

    strncat(io, string, MAX);
    strncat(io, "/io", MAX);
    system(io);
}

void dump_maps(char *string){
    char maps[MAX] = "cat /proc/";

    strncat(maps, string, MAX);
    strncat(maps, "/maps", MAX);
    system(maps);
}

void dump_limits(char *string){
    char limits[MAX] = "cat /proc/";

    strncat(limits, string, MAX);
    strncat(limits, "/limits", MAX);
    system(limits);
}

void aslr(){
    system("echo 2 | sudo tee /proc/sys/kernel/randomize_va_space");
}

void no_aslr(){
    system("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space");
}

void sig_handler(int signo){
    exit(0);
}

void no_time(){
    signal(SIGINT, sig_handler);

    for(;;){
        system("date -s '06 JUL 2018 12:00:00'");
        usleep(30000);
    }
}

void add(char *string){
    int total = 0;
    int length = strnlen(string, MAX) - 1;

    for(int i = 0; i <= length; i++){
        total = total + string[i];
    }

    printf("Decimal value: %d", total);
    printf("\n");
    printf("Hex value: %x", total);
    printf("\n");
}

void sub(char *string, int value){
    int length = strnlen(string, MAX) - 1;

    for(int i = 0; i <= length; i++){
        value = value - string[i];
    }

    printf("Decimal value: %d", value);
    printf("\n");
    printf("Hex value: %x", value);
    printf("\n");
}

void mult(char *string){
    int total = 1;
    int length = strnlen(string, MAX) - 1;

    for(int i = 0; i <= length; i++){
        total = total * string[i];
    }

    printf("Decimal value: %d", total);
    printf("\n");
    printf("Hex value: %x", total);
    printf("\n");
}

void shift(char *string, int shift){
    int length = strnlen(string, MAX) - 1;
    char rightshifted[MAX];
    char leftshifted[MAX];

    leftshifted[length + 1] = '\0';
    rightshifted[length + 1] = '\0';
    printf("Shifted right: ");

    for(int i = 0; i <= length; i++){
        rightshifted[i] = string[i] >> shift;
        printf("%x", rightshifted[i]);
    }

    printf("\n");
    printf("Shifted left: ");

    for(int e = 0; e <= length; e++){
        leftshifted[e] = string[e] << shift;
        printf("%x", leftshifted[e]);
    }

    printf("\n");
}

void xor(char *string, int xor){
    int length = strnlen(string, MAX) - 1;
    char xored[MAX];

    printf("Hex value: ");

    for(int i = 0; i <= length; i++){
        xored[i] = string[i] ^ xor;
        printf("%x", xored[i]);
    }

    xored[length + 1] = '\0';
    printf("\n");
    printf("String: ");
    printf("%s\n", xored);
}

void xors(char *string){
    int length = strnlen(string, MAX) - 1;
    char xored[length];
    int xor;

    xored[length + 1] = '\0';

    for(int i = 0; i <= 256; i++){
        printf("Hex value %d: ", i);

        for(int e = 0; e <= length; e++){
            xor = string[e] ^ i;
            xored[e] = (char)(xor);
            printf("%x", xored[e]);
        }

        printf("\n");
        printf("String    %d: ", i);
        printf("%s\n", xored);
    }
}

void getmd5(char *string){
    int length = strnlen(string, MAX);
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;

    MD5_Init(&ctx);
    MD5_Update(&ctx, string, length);
    MD5_Final(hash, &ctx);
    printf("\n");    

    for(int i = 0; i < 16; i++){
        printf("%02x", (unsigned int)hash[i]);
    }

    printf("\n");
}

void getsha1(char *string){
    int length = strnlen(string, MAX);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, string, length);
    SHA1_Final(hash, &ctx);
    printf("\n");    

    for(int i = 0; i < 20; i++){
        printf("%02x", (unsigned int)hash[i]);
    }

    printf("\n");    
}

void getsha256(char *string){
    int length = strnlen(string, MAX);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, length);
    SHA256_Final(hash, &ctx);
    printf("\n");    

    for(int i = 0; i < 32; i++){
        printf("%02x", (unsigned int)hash[i]);
    }

    printf("\n");
}

void getsha384(char *string){
    int length = strnlen(string, MAX);
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA512_CTX ctx;

    SHA384_Init(&ctx);
    SHA384_Update(&ctx, string, length);
    SHA384_Final(hash, &ctx);
    printf("\n");    

    for(int i = 0; i < 48; i++){
        printf("%02x", (unsigned int)hash[i]);
    }

    printf("\n");
}

void getsha512(char *string){
    int length = strnlen(string, MAX);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX ctx;

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, string, length);
    SHA512_Final(hash, &ctx);
    printf("\n");    

    for(int i = 0; i < 64; i++){
        printf("%02x", (unsigned int)hash[i]);
    }

    printf("\n");
}

void pick_general(char *option, char *string){
    if(&string[0] == NULL){
        return;
    }

    if(strncmp(option, "--reverse", MAX) == 0){
        reverse(string);
        exit(0);
    }else{
        return;
    }
}

void pick_general1(char *option, char *string, char *value){
    int val;

    if(&string[0] == NULL){
        return;
    }

    if(&value[0] == NULL){
        return;
    }

    val = atoi(value);

    if(strncmp(option, "--pattern", MAX) == 0){
        pattern(string, val);
        exit(0);
    }else{
        return;
    }
}

void pick_process(char *option, char *string){
    if(&string[0] == NULL){
        return;
    }

    if(strncmp(option, "--stack", MAX) == 0){
        dump_stack(string);
        exit(0);
    }else if(strncmp(option, "--status", MAX) == 0){
        dump_status(string);
        exit(0);
    }else if(strncmp(option, "--io", MAX) == 0){
        dump_io(string);
        exit(0);
    }else if(strncmp(option, "--maps", MAX) == 0){
        dump_maps(string);
        exit(0);
    }else if(strncmp(option, "--limits", MAX) == 0){
        dump_limits(string);
        exit(0);
    }else{
        return;
    }
}

void pick_system(char *option){
    if(strncmp(option, "--aslr", MAX) == 0){
        aslr();
        exit(0);
    }else if(strncmp(option, "--no-aslr", MAX) == 0){
        no_aslr();
        exit(0);
    }else if(strncmp(option, "--no-time", MAX) == 0){
        no_time();
        exit(0);
    }else{
        return;
    }
}

void pick_logic(char *option, char *string){
    if(&string[0] == NULL){
        return;
    }

    if(strncmp(option, "--add", MAX) == 0){
        add(string);
        exit(0);
    }else if(strncmp(option, "--mult", MAX) == 0){
        mult(string);
        exit(0);
    }else if(strncmp(option, "--xors", MAX) == 0){
        xors(string);
        exit(0);
    }else{
        return;
    }
}

void pick_logic1(char *option, char *string, char *value){
    int val;

    if(&value[0] == NULL){
        return;
    }

    if(&string[0] == NULL){
        return;
    }

    val = atoi(value);

    if(strncmp(option, "--sub", MAX) == 0){
        sub(string, val);
        exit(0);
    }else if(strncmp(option, "--shift", MAX) == 0){
        shift(string, val);
        exit(0);
    }else if(strncmp(option, "--xor", MAX) == 0){\
        xor(string, val);
        exit(0);
    }else{
        return;
    }    
}

void pick_hash(char *option, char *string){
    if(&string[0] == NULL){
        return;
    }

    if(strncmp(option, "--md5", MAX) == 0){
        getmd5(string);
        exit(0);
    }else if(strncmp(option, "--sha1", MAX) == 0){
        getsha1(string);
        exit(0);
    }else if(strncmp(option, "--sha256", MAX) == 0){
        getsha256(string);
        exit(0);
    }else if(strncmp(option, "--sha384", MAX) == 0){
        getsha384(string);
        exit(0);
    }else if(strncmp(option, "--sha512", MAX) == 0){
        getsha512(string);
        exit(0);
    }else{
        return;
    }
}

void usage(){
    printf("REhelper created by Andromeda\n");
    printf("This tool is designed to help with doing ");
    printf("reverse engineering tasks.\n");
    printf("Usage <option> <string> <number>\n\n");
    printf("General options:\n");
    printf("--reverse   <string>            reverses the string\n");
    printf("--pattern   <string> <number>   prints string the given ammount of times\n\n");
    printf("Process options:\n");
    printf("--stack     <string>            give process pid to dump its stack\n");
    printf("--status    <string>            give process pid to dump its status\n");
    printf("--io        <string>            give process pid to dump its IO data\n");
    printf("--maps      <string>            give process pid to dump its mappings\n");
    printf("--limits    <string>            give process pid to dump its limits\n\n");
    printf("System options:\n");
    printf("--aslr                          turns on system ASLR\n");
    printf("--no-aslr                       turns off system ASLR\n");
    printf("--no-time                       makes time stop\n\n");
    printf("Logic options:\n");
    printf("--add       <string>            adds value of string together\n");
    printf("--sub       <string> <number>   subtracts value of string from a value\n");
    printf("--mult      <string>            multiplies value of string together\n");
    printf("--shift     <string> <number>   bit shifts a string by a value\n");
    printf("--xor       <string> <number>   xores a string by a value\n");
    printf("--xors      <string>            xores a string by all 256 values\n\n");
    printf("Hashing algorithms:\n");
    printf("--md5       <string>            gets md5 of a string\n");
    printf("--sha1      <string>            gets sha1 of a string\n");
    printf("--sha256    <string>            gets sha256 of a string\n");
    printf("--sha384    <string>            gets sha384 of a string\n");
    printf("--sha512    <string>            gets sha512 of a string\n\n");
}

void handler(char *option, char *string, char *value){
    pick_general(option, string);
    pick_general1(option, string, value);
    pick_process(option, string);
    pick_system(option);
    pick_logic(option, string);
    pick_logic1(option, string, value);
    pick_hash(option, string);
    usage();

}

int main(int argc, char **argv){
    if(argc < 2 || argc > 4){
        usage();
        return 1;
    }

    handler(argv[1], argv[2], argv[3]);
    return 0;
}