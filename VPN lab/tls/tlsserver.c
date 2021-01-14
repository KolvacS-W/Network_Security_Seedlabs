#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BUFF_SIZE 2000
//#define DEBUG

#define CHK_SSL(err) if ((err) < 1) {ERR_print_errors_fp(stderr);exit(2);}
#define CHK_ERR(err, s) if ((err) == -1) {perror(s);exit(1);}

// global variant
struct sockaddr_in peerAddr;

int setupTCPServer();
void processRequest(int tunfd, int pipefd, int sockfd, SSL *ssl);
int LoginVerify(SSL *ssl, int conn);
void endRequest(SSL *ssl, int conn);

int createTunDevice() {
  int tunfd;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  tunfd = open("/dev/net/tun", O_RDWR);
  ioctl(tunfd, TUNSETIFF, &ifr);
  printf("TUN setup successfully\n");
  return tunfd;
}

void tun2pipe(int tunfd, int pipefd) {
  int len;
  char buff[BUFF_SIZE];

  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  buff[len] = '\0';
  // normal write, no ssl
  write(pipefd, buff, len);
}

void pipe2socket(int pipefd, int sockfd, SSL *ssl) {
  int len;
  char buff[BUFF_SIZE];

  bzero(buff, BUFF_SIZE);
  len = read(pipefd, buff, BUFF_SIZE);
  buff[len] = '\0';
  write(ssl, buff, len);
}

void socket2tun(int tunfd, int sockfd, SSL *ssl) {
  int len;
  char buff[BUFF_SIZE];

  bzero(buff, BUFF_SIZE);
  len = SSL_read(ssl, buff, BUFF_SIZE);
  buff[len] = '\0';
  SSL_write(tunfd, buff, len);
}



void processRequest(int tunfd, int pipefd, int sockfd, SSL *ssl) {
  while (1) {
    fd_set readFDSet;

    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(pipefd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    if (FD_ISSET(pipefd, &readFDSet)) pipe2socket(tunfd, sockfd, ssl);
    if (FD_ISSET(sockfd, &readFDSet)) socket2tun(tunfd, sockfd, ssl);
  }
}

void endRequest(SSL *ssl, int conn) {
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  close(conn);
}

int setupTCPServer() {
  struct sockaddr_in sa_server;
  int listen_sock;

  listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHK_ERR(listen_sock, "socket");
  memset(&sa_server, '\0', sizeof(sa_server));

  sa_server.sin_family = AF_INET;
  sa_server.sin_addr.s_addr = INADDR_ANY;
  sa_server.sin_port = htons(4433);

  int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));
  CHK_ERR(err, "bind");
  err = listen(listen_sock, 5);
  CHK_ERR(err, "listen");
  printf("TCP Setup successfully\n");
  return listen_sock;
}

int LoginVerify(SSL *ssl, int conn) {
  char *pch;
  char username[100];
  char password[1000];
  char request[BUFF_SIZE];

  // if not clear, the string would be weird
  memset(&username, 0, sizeof(username));
  memset(&password, 0, sizeof(password));
  memset(&request, 0, BUFF_SIZE);


  int len = SSL_read(ssl, request, BUFF_SIZE - 1);
  //printf("%d\n",len );
  request[len] = '\0';


  printf("request:  %s\n", request);
  // username[0]='s',username[1]='e',username[2]='e',username[3]='d';
  // //password="dees";
  // printf("username %s \n",username);
  // printf("password %s \n",password);
  // printf("request  %s\n", request);

#ifdef DEBUG
  printf("Logging in:%s\n", request);
#endif

  // username
  pch = strtok(request, " ");
  /*
  if (!pch) {
    printf("Invalid username\n");
    return -1;
  }
  */
  strcpy(username, pch);
#ifdef DEBUG
  printf("Username:%s\n", username);
#endif

  // password
  pch = strtok(NULL, " ");
  if (!pch) {
    printf("Invalid password\n");
    return -1;
  }
  strcpy(password, pch);
#ifdef DEBUG
  printf("Password:%s\n", password);
#endif

  // check the shadow
  struct spwd *pw;
  char *epasswd;
  pw = getspnam(username);
  if (pw == NULL) {
    printf("Invalid account\n");
    return -1;
  }

  // return the result
  epasswd = crypt(password, pw->sp_pwdp);
  char fail[] = "fail";
  char success[] = "success";
  if (strcmp(epasswd, pw->sp_pwdp)) {
    printf("Username and password do not match\n");
    SSL_write(ssl, fail, strlen(fail));
    return -1;
  }
  SSL_write(ssl, success, strlen(success));
  return 1;
}

int main(int argc, char *argv[]) {
  int fd[2];
  int tunfd = createTunDevice();
  printf("createTunDevice.....\n" );
  
  pipe(fd);
  if (fork() > 0) //parent
  {
    printf("parent\n");                 
    close(fd[0]);
    while (1) 
    {
      fd_set readFDSet;
      FD_ZERO(&readFDSet);
      FD_SET(tunfd, &readFDSet);
      select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

      if (FD_ISSET(tunfd, &readFDSet)) 
        tun2pipe(tunfd, fd[1]);//将收到的internal网络的packet广播发送给pipe另一端的子进程
    }
    return 0;
  } 

  else  //child
  {
    printf("child\n");
    close(fd[1]);

    size_t client_len;
    struct sockaddr_in sa_client;
    int sockfd = setupTCPServer();

    while (1) {
      int conn = accept(sockfd, (struct sockaddr *)&sa_client, &client_len);
      printf("accept\n");
      if (fork() == 0) //每accept一个client连接，就创建子进程
        {
          // child process
          close(sockfd);

          printf("%d: Start\n", getpid());

          //————————————SSL INIT——————————————————
          SSL_METHOD *meth;
          SSL_CTX* ctx;
          SSL *ssl;
          // Step 0: OpenSSL library initialization 
          // This step is no longer needed as of version 1.1.0.
          SSL_library_init();
          SSL_load_error_strings();
          SSLeay_add_ssl_algorithms();

          // Step 1: SSL context initialization
          meth = (SSL_METHOD *)TLSv1_2_method();
          ctx = SSL_CTX_new(meth);
          SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
          // Step 2: Set up the server certificate and private key
          SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
          SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
          // Step 3: Create a new SSL structure for a connection
          ssl = SSL_new (ctx);


          SSL_set_fd(ssl, conn);
          int err = SSL_accept(ssl);
          int errcode = SSL_get_error(ssl, err);

          printf("%d: Handshake\n", getpid());
          //CHK_SSL(err);
          if (LoginVerify(ssl, conn) != 1) {
            printf("%d: Login Fail！\n", getpid());
            endRequest(ssl, conn);
            return 0;
          }
          printf("%d: Login success!\n", getpid());

          //进入处理逻辑
          printf("processing request.....\n");
          processRequest(tunfd, fd[0], conn, ssl);

          printf("%d: Exit\n", getpid());
          endRequest(ssl, conn);
          return 0;
        } 
        else 
        {
      // parent
      close(conn);
      //close(tunfd);
        }
    }
  }
}