#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main() {
    // 初始化SSL库
    SSL_library_init();
    
    // 创建SSL上下文对象
    // SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    
    // 设置SSL最小协议版本为TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // 检查SSL上下文对象是否创建成功
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SSL context.\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 加载服务器证书和私钥
    // 使用PEM格式的证书和私钥文件
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server certificate.\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server private key.\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 创建TCP套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 本地回环地址
    server_addr.sin_port = htons(443);  // HTTPS默认端口
    
    // 将套接字与服务器地址绑定
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        fprintf(stderr, "Error binding socket.\n");
        return 1;
    }

    // 监听套接字，等待连接
    if (listen(sockfd, 1) != 0) {
        fprintf(stderr, "Error listening on socket.\n");
        return 1;
    }

    printf("Server is listening on port 443...\n");

    while (1) {
        // 接受客户端连接请求
        int clientfd = accept(sockfd, NULL, NULL);
        if (clientfd < 0) {
            fprintf(stderr, "Error accepting connection.\n");
            return 1;
        }

        // 创建SSL对象
        SSL* ssl = SSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "Error creating SSL structure.\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }

        // 将SSL对象绑定到客户端套接字上
        SSL_set_fd(ssl, clientfd);

        // 在SSL上下文对象上进行SSL握手
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Error accepting SSL connection.\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }

        // 读取客户端发送的数据
        char buffer[1024];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received: %s\n", buffer);

            // 将接收到的消息回显给客户端
            SSL_write(ssl, buffer, bytes);
        }

        // 关闭SSL连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientfd);
    }

    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
