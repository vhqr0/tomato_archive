#ifndef TOMATO_CLI_H
#define TOMATO_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

void forward(const char *laddr, const char *lport, const char *raddr, const char *rport);
void tls2raw(const char *laddr, const char *lport, const char *raddr, const char *rport,
             const char *certfile, const char *keyfile, const char *password);
void raw2tls(const char *laddr, const char *lport, const char *raddr, const char *rport,
             const char *hostname, const char *cafile);
void socks5(const char *addr, const char *port, const char *username,
            const char *password, int strict);
void socks5s(const char *addr, const char *port, const char *username,
             const char *password, const char *certfile, const char *keyfile,
             const char *kpassword, int strict);
void set_default_rule(int rule);
void add_ip_rule(const char *mmdb, int rule);
void add_domain_rule(const char *domain, int rule);
void clear_rules();
void socks5f(const char *laddr, const char *lport, const char *lusername,
             const char *lpassword, const char *raddr, const char *rport,
             const char *rusername, const char *rpassword, const char *hostname,
             const char *cafile);
void acceptor(const char *caddr, const char *cport, const char *addr, const char *port,
              const char *username, const char *password, const char *certfile,
              const char *keyfile, const char *kpassword);
void connector(const char *aaddr, const char *aport, const char *addr, const char *port,
               const char *username, const char *password, const char *hostname,
               const char *cafile);

#ifdef __cplusplus
}
#endif

#endif /* TOMATO_CLI_H */
