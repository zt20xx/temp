#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

int main()
{
    mbedtls_net_context listen_fd, client_fd; // 定义监听套接字和客户端套接字
    mbedtls_entropy_context entropy; // 定义熵源对象
    mbedtls_ctr_drbg_context ctr_drbg; // 定义随机数生成器对象
    const char *pers = "ssl_server"; // 定义个人化字符串

    mbedtls_net_init(&listen_fd); // 初始化监听套接字对象
    mbedtls_net_init(&client_fd); // 初始化客户端套接字对象
    mbedtls_entropy_init(&entropy); // 初始化熵源对象
    mbedtls_ctr_drbg_init(&ctr_drbg); // 初始化随机数生成器对象

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0)
    {
        printf("Failed to initialize random number generator.\n");
        goto exit;
    }

    mbedtls_x509_crt srvcert; // 定义服务器证书对象
    mbedtls_x509_crt_init(&srvcert); // 初始化服务器证书对象
    if (mbedtls_x509_crt_parse_file(&srvcert, "server.crt") != 0)
    {
        printf("Failed to load server certificate.\n");
        goto exit;
    }
    mbedtls_pk_context pkey; // 定义私钥对象
    mbedtls_pk_init(&pkey); // 初始化私钥对象
    if (mbedtls_pk_parse_keyfile(&pkey, "server.key", "", NULL, 0) != 0)
    {
        printf("Failed to load server private key.\n");
        goto exit;
    }
    mbedtls_ssl_config conf; // 定义SSL配置对象
    mbedtls_ssl_config_init(&conf); // 初始化SSL配置对象
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        printf("Failed to set SSL configuration defaults.\n");
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg); // 设置随机数生成器
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL); // 设置CA证书链
    if (mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey) != 0) // 设置服务器证书和私钥
    {
        printf("Failed to configure SSL own certificate.\n");
        goto exit;
    }
    mbedtls_ssl_context ssl; // 定义SSL上下文对象

while (1)
{

    mbedtls_ssl_init(&ssl); // 初始化SSL上下文对象
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) // 设置SSL上下文对象
    {
        printf("Failed to set up SSL context.\n");
        goto exit;
    }

    if (mbedtls_net_bind(&listen_fd, NULL, "443", MBEDTLS_NET_PROTO_TCP) != 0) // 将监听套接字绑定到本地回环地址的443端口
    {
        printf("Failed to bind socket.\n");
        goto exit;
    }

    printf("Server is listening on port 443...\n");

    if (mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL) != 0) // 接受客户端连接
    {
        printf("Failed to accept incoming connection.\n");
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL); // 设置SSL连接使用的读写函数

    if (mbedtls_ssl_handshake(&ssl) != 0) // 进行SSL握手
    {
        printf("Failed to perform SSL handshake.\n");
        goto exit;
    }

    char buffer[1024];
    int bytes = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, sizeof(buffer) - 1); // 从SSL连接中读取数据
    if (bytes > 0)
    {
        buffer[bytes] = '\0';
        printf("Received: %s\n", buffer);

        // 回显收到的消息
        mbedtls_ssl_write(&ssl, (unsigned char *)buffer, bytes);
    }

    mbedtls_ssl_close_notify(&ssl); // 关闭SSL连接
    mbedtls_net_free(&client_fd); // 释放客户端套接字
    mbedtls_net_free(&listen_fd); // 释放监听套接字

}

exit:
    mbedtls_ssl_close_notify(&ssl); // 关闭SSL连接
    mbedtls_net_free(&client_fd); // 释放客户端套接字
    mbedtls_net_free(&listen_fd); // 释放监听套接字
    mbedtls_ssl_free(&ssl); // 释放SSL上下文对象
    mbedtls_ssl_config_free(&conf); // 释放SSL配置对象
    mbedtls_x509_crt_free(&srvcert); // 释放服务器证书对象
    mbedtls_pk_free(&pkey); // 释放私钥对象
    mbedtls_entropy_free(&entropy); // 释放熵源对象
    mbedtls_ctr_drbg_free(&ctr_drbg); // 释放随机数生成器对象

    return 0;
}
