#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 8080

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
                 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
                 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                 43, 44, 45, 46, 47, 48, 49, 50, 51};

int b64_isvalidchar(char c)
{
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 1;
    if (c >= 'a' && c <= 'z')
        return 1;
    if (c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

void b64_generate_decode_table()
{
    int inv[80];
    size_t i;

    memset(inv, -1, sizeof(inv));
    for (i = 0; i < sizeof(b64chars) - 1; i++)
    {
        inv[b64chars[i] - 43] = i;
    }
}

size_t b64_encoded_size(size_t inlen)
{
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

char *b64_encode(const unsigned char *in, size_t len)
{
    char *out;
    size_t elen;
    size_t i;
    size_t j;
    size_t v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out = malloc(elen + 1);
    out[elen] = '\0';

    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        v = in[i];
        v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
        v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        if (i + 1 < len)
        {
            out[j + 2] = b64chars[(v >> 6) & 0x3F];
        }
        else
        {
            out[j + 2] = '=';
        }
        if (i + 2 < len)
        {
            out[j + 3] = b64chars[v & 0x3F];
        }
        else
        {
            out[j + 3] = '=';
        }
    }

    return out;
}

size_t b64_decoded_size(const char *in)
{
    size_t len;
    size_t ret;
    size_t i;

    if (in == NULL)
        return 0;

    len = strlen(in);
    ret = len / 4 * 3;

    for (i = len; i-- > 0;)
    {
        if (in[i] == '=')
        {
            ret--;
        }
        else
        {
            break;
        }
    }

    return ret;
}

int b64_decode(const char *in, unsigned char *out, size_t outlen)
{
    size_t len;
    size_t i;
    size_t j;
    int v;

    if (in == NULL || out == NULL)
        return 0;

    len = strlen(in);
    if (outlen < b64_decoded_size(in) || len % 4 != 0)
        return 0;

    for (i = 0; i < len; i++)
    {
        if (!b64_isvalidchar(in[i]))
        {
            return 0;
        }
    }

    for (i = 0, j = 0; i < len; i += 4, j += 3)
    {
        v = b64invs[in[i] - 43];
        v = (v << 6) | b64invs[in[i + 1] - 43];
        v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
        v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

        out[j] = (v >> 16) & 0xFF;
        if (in[i + 2] != '=')
            out[j + 1] = (v >> 8) & 0xFF;
        if (in[i + 3] != '=')
            out[j + 2] = v & 0xFF;
    }

    return 1;
}

void add_contact(char *enc_data, int new_socket)
{
    // create a file if doesn't exist
    FILE *fp = fopen("phone.txt", "a+");
    char line[1024];
    int flag = 1;
    // char unsuc = '0';
    char *dec_data;
    char *dec;
    char *sent;
    size_t sent_len;
    size_t dec_data_len;

    dec_data_len = b64_decoded_size(enc_data) + 1;
    dec_data = malloc(dec_data_len);

    b64_decode(enc_data, (unsigned char *)dec_data, dec_data_len);

    for (int i = 0; i < strlen(dec_data); i++)
    {
        if (dec_data[i] == '|')
        {
            dec_data[i] = '\0';
            break;
        }
    }

    // printf("%s,,,%s", out, dec);
    // bzero(dec, sizeof(dec));

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        // printf("strlen : %ld, sizeof: %ld", strlen(line), sizeof(line));

        for (int i = 0; i < sizeof(line); i++)
        {
            if (line[i] == '\n')
            {
                line[i] = '\0';
            }
        }

        sent = line;
        // printf("sent : %s\n", sent);
        sent_len = b64_decoded_size(sent) + 1;
        dec = malloc(sent_len);

        b64_decode(sent, (unsigned char *)dec, sent_len);

        for (int i = 0; i < strlen(dec); i++)
        {
            if (dec[i] == '|')
            {
                dec[i] = '\0';
                break;
            }
        }

        // printf("sent : %s\n", sent);

        // printf("%s", dec);

        // if_present(dec, out, &flag);

        flag = strcmp(dec_data, dec);
        // printf("\nSearched Name : %s\nAvailable Name : %s", out, dec);
        // printf("\nMatch Found :%d\n", flag);

        if (flag == 0)
        {
            // send(new_socket, line, sizeof(line), 0);
            // fputs(line, stdout);
            printf("Contact Not Added (name already exists)!!\n");
            printf("\n---------------------------------------------------\n");
            break;
        }

        bzero(line, sizeof(line));
    }

    if (flag != 0)
    {
        fprintf(fp, "%s\n", enc_data);
        printf("Contact Added Successfully!!\n");
        printf("\n---------------------------------------------------\n");
    }

    fclose(fp);
}

// out_len = b64_decoded_size(line) + 1;
// out = malloc(out_len);
// b64_decode(line, (unsigned char *)out, out_len);

void list_contact(int new_socket, char *out)
{
    // bzero(out, sizeof(out));
    FILE *fptr = fopen("phone.txt", "r");
    char line[1024];

    while (fgets(line, sizeof(line), fptr) != NULL)
    {
        // out_len = b64_decoded_size(line) + 1;
        // out = malloc(out_len);
        // b64_decode(line, (unsigned char *)out, out_len);
        // printf("strlen : %ld, sizeof: %ld", strlen(line), sizeof(line));

        for (int i = 0; i < sizeof(line); i++)
        {
            if (line[i] == '\n')
            {
                line[i] = '\0';
            }
        }

        send(new_socket, line, sizeof(line), 0);
        // fputs(line, stdout);
        bzero(line, sizeof(line));
    }

    send(new_socket, "0", sizeof("0"), 0);

    fclose(fptr);
}

void search_contact(int new_socket, char *out)
{
    FILE *fptr = fopen("phone.txt", "r");
    char line[1024];
    int flag = 1;
    // char unsuc = '0';
    char *dec;
    char *sent;
    size_t sent_len;

    // printf("%s,,,%s", out, dec);
    // bzero(dec, sizeof(dec));

    while (fgets(line, sizeof(line), fptr) != NULL)
    {
        // printf("strlen : %ld, sizeof: %ld", strlen(line), sizeof(line));

        for (int i = 0; i < sizeof(line); i++)
        {
            if (line[i] == '\n')
            {
                line[i] = '\0';
            }
        }

        sent = line;
        // printf("sent : %s\n", sent);
        sent_len = b64_decoded_size(sent) + 1;
        dec = malloc(sent_len);

        b64_decode(sent, (unsigned char *)dec, sent_len);

        for (int i = 0; i < strlen(dec); i++)
        {
            if (dec[i] == '|')
            {
                dec[i] = '\0';
                break;
            }
        }

        // printf("sent : %s\n", sent);

        // printf("%s", dec);

        // if_present(dec, out, &flag);

        flag = strcmp(dec, out);
        // printf("\nSearched Name : %s\nAvailable Name : %s", out, dec);
        // printf("\nMatch Found :%d\n", flag);

        if (flag == 0)
        {
            send(new_socket, line, sizeof(line), 0);
            // fputs(line, stdout);
            break;
        }

        bzero(line, sizeof(line));
    }

    if (flag != 0)
    {
        send(new_socket, "0", sizeof("0"), 0);
    }

    fclose(fptr);
}

void delete_contact(int new_socket, char *out)
{
    FILE *fptr = fopen("phone.txt", "r");
    FILE *newptr = fopen("phone1.txt", "w");
    char line[1024];
    int flag = 1, j = 0;
    // char unsuc = '0';
    char *comp_decode;
    char *dec;
    char *sent;
    size_t sent_len;

    // printf("%s,,,%s", out, dec);
    // bzero(dec, sizeof(dec));

    while (fgets(line, sizeof(line), fptr) != NULL)
    {
        // printf("strlen : %ld, sizeof: %ld", strlen(line), sizeof(line));

        for (int i = 0; i < sizeof(line); i++)
        {
            if (line[i] == '\n')
            {
                line[i] = '\0';
            }
        }

        sent = line;
        // printf("sent : %s\n", sent);
        sent_len = b64_decoded_size(sent) + 1;
        dec = malloc(sent_len);
        comp_decode = malloc(sent_len);

        b64_decode(sent, (unsigned char *)comp_decode, sent_len);
        b64_decode(sent, (unsigned char *)dec, sent_len);

        for (int i = 0; i < strlen(comp_decode); i++)
        {
            if (comp_decode[i] == '|')
            {
                dec[i] = '\0';
                break;
            }
        }

        flag = strcmp(dec, out);
        // printf("\nSearched Name : %s\nAvailable Name : %s", out, dec);
        // printf("\nMatch Found :%d\n", flag);

        if (flag == 0)
        {
            // fputs(line, stdout);
        }
        else
        {
            fprintf(newptr, "%s\n", line);
        }
        bzero(line, sizeof(line));
    }
    fclose(newptr);
    fclose(fptr);

    remove("phone.txt");
    rename("phone1.txt", "phone.txt");
}

int main(int argc, char const *argv[])
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    // char *hello = "Hello from server";

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        // perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        // perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        // perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        // perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0)
    {
        // perror("accept");
        exit(EXIT_FAILURE);
    }

    // Encryption Start

    // Assign variables

    // recieve data from client
    char recv_data[1024];

    for (;;)
    {

        char *out;
        size_t out_len;

        bzero(recv_data, sizeof(recv_data));
        valread = read(new_socket, recv_data, sizeof(recv_data));
        // printf("%s\n", recv_data);

        // create a pointer to that recieved data
        char *enc = recv_data;
        // printf("Encrypted : %s", enc);

        // Decode data
        out_len = b64_decoded_size(enc) + 1;
        out = malloc(out_len);

        if (!b64_decode(enc, (unsigned char *)out, out_len))
        {
            // printf("Decode Failure\n");
            return 1;
        }
        out[out_len-1] = '\0';

        // printf("dec:     '%s'\n", out);
        // Decode end

        char choice = out[0];
        // printf("%c", choice);

        switch (choice)
        {
        case '0':
            exit(0);
            break;

        case '1':
            out = &out[1];
            // printf("contact added string : %s\n", out);
            enc = b64_encode((const unsigned char *)out, strlen(out));
            b64_decode(enc, (unsigned char *)out, out_len);
            // printf("%s", out);
            add_contact(enc, new_socket);
            break;

        case '2':
            out = &out[1];
            // printf("contact added string : %s\n", out);
            delete_contact(new_socket, out);
            printf("Contact Deleted Successfully!!\n");
            printf("\n---------------------------------------------------\n");
            break;

        case '3':
            out = &out[1];
            // printf("contact added string : %s\n", out);
            search_contact(new_socket, out);
            printf("Contact Searched!!\n");
            printf("\n---------------------------------------------------\n");
            break;

        case '4':
            list_contact(new_socket, out);
            printf("Listed All The Contacts Successfully!!\n");
            printf("\n---------------------------------------------------\n");
            break;

        default:
            break;
        }
    }
    return 0;
}
