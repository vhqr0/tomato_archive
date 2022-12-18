#include "tomato.hpp"

void help(const char *program) {
  std::printf("usage: %s [OPTION]...\n", program);
  std::puts("-h, --help           show this message");
  std::puts("-c, --client         trojan client mode");
  std::puts("-s, --server         trojan server mode");
  std::puts("-p, --password       trojan password");
  std::puts("-i, --in             local endpoint");
  std::puts("-o, --out            remote endpoint");
  std::puts("-H, --hostname       tls client server hostname");
  std::puts("    --ca             tls client ca file");
  std::puts("    --cert           tls server cert file");
  std::puts("    --key            tls server key file");
  std::puts("    --keypassword    tls server key file password");
  std::puts("    --drb            domain rules set block and may be set db");
  std::puts("    --drp            domain rules set proxy and may be set db");
  std::puts("    --drd            domain rules set direct and may be set db");
  std::puts("    --irb            domain rules set block or may be add db");
  std::puts("    --irp            domain rules set proxy or may be add db");
  std::puts("    --ird            domain rules set direct or may be add db");
  std::exit(1);
}

int main(int argc, char **argv) {
  enum {
    loptca,
    loptcert,
    loptkey,
    loptkeypassword,
    loptdrb,
    loptdrp,
    loptdrd,
    loptirb,
    loptirp,
    loptird,
  };
  int longflag, longind;
  struct option longopts[] = {
    {"help", no_argument, NULL, 'h'},
    {"client", no_argument, NULL, 'c'},
    {"server", no_argument, NULL, 's'},
    {"password", required_argument, NULL, 'p'},
    {"in", required_argument, NULL, 'i'},
    {"out", required_argument, NULL, 'o'},
    {"hostname", required_argument, NULL, 'H'},
    {"ca", optional_argument, &longflag, loptca},
    {"cert", required_argument, &longflag, loptcert},
    {"key", required_argument, &longflag, loptkey},
    {"keypassword", required_argument, &longflag, loptkeypassword},
    {"drb", optional_argument, &longflag, loptdrb},
    {"drp", optional_argument, &longflag, loptdrp},
    {"drd", optional_argument, &longflag, loptdrd},
    {"irb", optional_argument, &longflag, loptirb},
    {"irp", optional_argument, &longflag, loptirp},
    {"ird", optional_argument, &longflag, loptird},
    {0, 0, 0, 0},
  };

  enum { socks5_mode, trojan_client_mode, trojan_server_mode } mode = socks5_mode;
  std::string password = "", in = "", out = "", tls_hostname = "", ca = "certs/cert.pem",
              cert = "certs/cert.pem", key = "certs/key.pem", keypassword = "";

  char c;
  while ((c = getopt_long(argc, argv, "hcsp:i:o:H:", longopts, &longind)) >= 0) {
    switch (c) {
    case 'h':
      help(argv[0]);
      break;
    case 'c':
      mode = trojan_client_mode;
      break;
    case 's':
      mode = trojan_server_mode;
      break;
    case 'p':
      password = std::string(optarg);
      break;
    case 'i':
      in = std::string(optarg);
      break;
    case 'o':
      out = std::string(optarg);
      break;
    case 'H':
      tls_hostname = std::string(optarg);
      break;
    case 0:
      switch (longflag) {
      case loptca:
        ca = std::string(optarg ? optarg : "");
        break;
      case loptcert:
        cert = std::string(optarg);
        break;
      case loptkey:
        key = std::string(optarg);
        break;
      case loptkeypassword:
        keypassword = std::string(optarg);
        break;
      case loptdrb:
        domain_rules_set_default_rule(RULE_BLOCK);
        if (optarg)
          domain_rules_set_db(optarg);
        break;
      case loptdrp:
        domain_rules_set_default_rule(RULE_PROXY);
        if (optarg)
          domain_rules_set_db(optarg);
        break;
      case loptdrd:
        domain_rules_set_default_rule(RULE_DIRECT);
        if (optarg)
          domain_rules_set_db(optarg);
        break;
      case loptirb:
        if (optarg)
          ip_rules_add_db(optarg, RULE_BLOCK);
        else
          ip_rules_set_default_rule(RULE_BLOCK);
        break;
      case loptirp:
        if (optarg)
          ip_rules_add_db(optarg, RULE_PROXY);
        else
          ip_rules_set_default_rule(RULE_PROXY);
        break;
      case loptird:
        if (optarg)
          ip_rules_add_db(optarg, RULE_DIRECT);
        else
          ip_rules_set_default_rule(RULE_DIRECT);
        break;
      default:
        fprintf(stderr, "unrecognized long flag: %d\n", longflag);
        help(argv[0]);
      }
      break;
    default:
      fprintf(stderr, "unrecognized option: %c\n", c);
      help(argv[0]);
    }
  }

  std::regex re("^([^:\\[\\]]+|\\[.*\\])?(:([0-9a-zA-Z]+))?$");
  std::match_results<std::string::iterator> res;
  std::string hostname, servicename, server_hostname, server_servicename;
  if (!std::regex_search(in.begin(), in.end(), res, re)) {
    std::cerr << "unrecognized url: " << in << std::endl;
    std::exit(-1);
  }
  hostname = res[1];
  servicename = res[3];
  if (hostname.empty())
    hostname = "localhost";
  if (hostname[0] == '[')
    hostname = hostname.substr(1, hostname.length() - 2);
  if (servicename.empty())
    servicename = mode == trojan_server_mode ? "443" : "1080";
  if (!std::regex_search(out.begin(), out.end(), res, re)) {
    std::cerr << "unrecognized url: " << out << std::endl;
    std::exit(-1);
  }
  server_hostname = res[1];
  server_servicename = res[3];
  if (server_hostname.empty())
    server_hostname = "localhost";
  if (server_hostname[0] == '[')
    server_hostname = server_hostname.substr(1, server_hostname.length() - 2);
  if (server_servicename.empty())
    server_servicename = "443";
  if (tls_hostname.empty())
    tls_hostname = server_hostname;

  switch (mode) {
  case socks5_mode:
    socks5_main(hostname, servicename);
    break;
  case trojan_client_mode:
    trojanc_main(hostname, servicename, server_hostname, server_servicename, password, tls_hostname,
                 ca);
    break;
  case trojan_server_mode:
    trojans_main(hostname, servicename, password, cert, key, keypassword);
    break;
  }
}
