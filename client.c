#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
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

void print_prompt()
{
    printf("---------------------------------------------------\n0) Exit\n1) Add Contact\n2) Delete Contact\n3) Search Contact\n4) List all contacts\n---------------------------------------------------\nYour Choice : ");
}

int main(int argc, char const *argv[])
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    // char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        // printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        // printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        // printf("\nConnection Failed \n");
        return -1;
    }

    // Encryption Start
    char contact_name[512];
    char contact_number[512];
    char sent_data[1024];
    
    char recved[1024];
    
    char make_data[1024];

    for (;;)
    {
        char *enc;
        char *data;
        char *out;
        size_t out_len;
        int counter;
        int status, cnt = 0;
        int choice;

        print_prompt();
        scanf("%d", &choice);

        bzero(contact_name, sizeof(contact_name));
        bzero(contact_number, sizeof(contact_number));
        bzero(sent_data, sizeof(sent_data));
        bzero(recved, sizeof(recved));
        bzero(make_data, sizeof(make_data));

        // char *temp_out;
        // size_t temp_out_len;

        bzero(make_data, sizeof(make_data));

        switch (choice)
        {
        case 0:
            send(sock, "0", strlen("0"), 0);
            exit(0);
            break;

        case 1:
            printf("\n---------------------------------------------------\n");
            printf("Enter contact name : ");
            scanf("%s", contact_name);
            printf("Enter contact number : ");
            scanf("%s", contact_number);
            printf("\n---------------------------------------------------\n");

            strncat(make_data, "1", strlen("1"));
            strncat(make_data, contact_name, strlen(contact_name));
            strncat(make_data, "|", strlen("|"));
            strncat(make_data, contact_number, strlen(contact_number));

            data = make_data;

            // printf("data:    '%s'\n", data);

            enc = b64_encode((const unsigned char *)data, strlen(data));
            // printf("encoded: '%s'\n", enc);

            counter = strlen(enc) + 1;
            for (int i = 0; i < counter; i++)
            {
                sent_data[i] = enc[i];
            }

            // printf("encoded sent_enc: '%s'\n", sent_data);

            // printf("dec size %s data size\n", b64_decoded_size(enc) == strlen(data) ? "==" : "!=");
            // Encryption End

            bzero(make_data, sizeof(make_data));

            send(sock, sent_data, strlen(sent_data), 0);

            bzero(sent_data, sizeof(sent_data));
            break;

        case 2:
            printf("\n---------------------------------------------------\n");
            printf("Enter contact name to delete : ");
            scanf("%s", contact_name);
            printf("\n---------------------------------------------------\n");

            strncat(make_data, "2", strlen("2"));
            strncat(make_data, contact_name, strlen(contact_name));

            data = make_data;

            // printf("data:    '%s'\n", data);

            enc = b64_encode((const unsigned char *)data, strlen(data));
            // printf("encoded: '%s'\n", enc);

            counter = strlen(enc) + 1;
            for (int i = 0; i < counter; i++)
            {
                sent_data[i] = enc[i];
            }

            // printf("encoded sent_enc: '%s'\n", sent_data);

            send(sock, sent_data, strlen(sent_data), 0);

            bzero(make_data, sizeof(make_data));
            bzero(sent_data, sizeof(sent_data));

            bzero(recved, sizeof(recved));
            printf("\n---------------------------------------------------\n");
            printf("Contact Deleted (if found)!!\n");
            printf("\n---------------------------------------------------\n");
            // status = read(sock, recved, sizeof(recved));

            break;

        case 3:
            printf("\n---------------------------------------------------\n");
            printf("Enter contact name to search : ");
            scanf("%s", contact_name);
            printf("\n---------------------------------------------------\n");

            strncat(make_data, "3", strlen("3"));
            strncat(make_data, contact_name, strlen(contact_name));

            data = make_data;

            // printf("data:    '%s'\n", data);

            enc = b64_encode((const unsigned char *)data, strlen(data));
            // printf("encoded: '%s'\n", enc);

            counter = strlen(enc) + 1;
            for (int i = 0; i < counter; i++)
            {
                sent_data[i] = enc[i];
            }

            // printf("encoded sent_enc: '%s'\n", sent_data);

            send(sock, sent_data, strlen(sent_data), 0);

            bzero(make_data, sizeof(make_data));
            bzero(sent_data, sizeof(sent_data));

            bzero(recved, sizeof(recved));
            status = read(sock, recved, sizeof(recved));

            int flag = 0;
            char temp_contact_name[1024];
            char temp_conatct_number[1024];
            int temp = 0;

            if (status >= 0)
            {
                char *enc_ptr = recved;
                out_len = b64_decoded_size(enc_ptr) + 1;

                out = malloc(out_len);

                b64_decode(enc_ptr, (unsigned char *)out, out_len);
                out[out_len] = '\0';
                // printf("recieved: %c", recved[0]);

                if (recved[0] != '0')
                {
                    for (int i = 0; i < strlen(recved); i++)
                    {
                        if (out[i] != '|' && flag == 0)
                        {
                            temp_contact_name[i] = out[i];
                            temp++;
                        }
                        else if (out[i] == '|')
                        {
                            flag = 1;
                            temp_contact_name[i] = '\0';
                            temp++;
                            continue;
                        }
                        else if (flag == 1)
                        {
                            temp_conatct_number[i - temp] = out[i];
                        }
                    }
                    printf("\n---------------------------------------------------\n");
                    printf("\ncontact Name : %s\nContact Number: %s\n", temp_contact_name, temp_conatct_number);
                    printf("\n---------------------------------------------------\n");
                }

                else
                {
                    printf("\n---------------------------------------------------\n");
                    printf("\nNo such contact availabel in file\n");
                    printf("\n---------------------------------------------------\n");
                }

                // free(out);
                bzero(recved, sizeof(recved));
            }
            break;

        case 4:
            printf("\n---------------------------------------------------\n");
            printf("All Phonebook Records :");
            printf("\n---------------------------------------------------\n");
            strncat(make_data, "4", strlen("4"));

            data = make_data;

            // printf("data:    '%s'\n", data);

            enc = b64_encode((const unsigned char *)data, strlen(data));
            // printf("encoded: '%s'\n", enc);

            counter = strlen(enc) + 1;
            for (int i = 0; i < counter; i++)
            {
                sent_data[i] = enc[i];
            }

            // printf("encoded sent_enc: '%s'\n", sent_data);

            // printf("dec size %s data size\n", b64_decoded_size(enc) == strlen(data) ? "==" : "!=");
            // Encryption End

            send(sock, sent_data, strlen(sent_data), 0);

            bzero(make_data, sizeof(make_data));
            bzero(sent_data, sizeof(sent_data));

            for (;;)
            {
                bzero(recved, sizeof(recved));
                status = read(sock, recved, sizeof(recved));

                char *enc_ptr = recved;
                out_len = b64_decoded_size(enc_ptr) + 1;

                out = malloc(out_len);

                // printf("\nstatus : %d\n", status);

                if (recved[0] == '0')
                {
                    printf("\n---------------------------------------------------\n");
                    printf("That's what we have...");
                    printf("\n---------------------------------------------------\n");
                    break;
                }
                else
                {
                    cnt++;
                    int flag = 0;
                    char temp_contact_name[1024];
                    char temp_conatct_number[1024];
                    int temp = 0;

                    // printf("Phonebook data %d : %s\n", cnt, recved);

                    b64_decode(enc_ptr, (unsigned char *)out, out_len);
                    out[out_len] = '\0';

                    // printf("-------%s, %d-------", out, out_len);

                    // printf("Phonebook data decrypted %d : %s\n", cnt, out);
                    for (int i = 0; i < strlen(recved); i++)
                    {
                        if (out[i] != '|' && flag == 0)
                        {
                            temp_contact_name[i] = out[i];
                            temp++;
                        }
                        else if (out[i] == '|')
                        {
                            flag = 1;
                            temp_contact_name[i] = '\0';
                            temp++;
                            continue;
                        }
                        else if (flag == 1)
                        {
                            temp_conatct_number[i - temp] = out[i];
                        }
                    }
                    printf("\n---------------------------------------------------\n");
                    printf("contact %d Name : %s\nContact %d Number: %s\n", cnt, temp_contact_name, cnt, temp_conatct_number);
                    printf("\n---------------------------------------------------\n");
                    bzero(recved, sizeof(recved));
                    // // free(out);
                }
            }
            break;

        default:
            break;
        }
    }

    return 0;
}