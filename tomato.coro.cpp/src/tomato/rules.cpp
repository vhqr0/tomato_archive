#include "tomato.hpp"

///////////////////////////////////////////////////////////////////////////////
//                                domain rules                               //
///////////////////////////////////////////////////////////////////////////////

bool domain_rules_enabled = false;
int domain_rules_default_rule = RULE_PROXY;
sqlite3 *domain_rules_db = nullptr;
std::unordered_map<std::string, int> domain_rules_cache;

void domain_rules_set_default_rule(int rule) { domain_rules_default_rule = rule; }

void domain_rules_set_db(const char *dbfile) {
  domain_rules_enabled = true;
  if (domain_rules_db)
    sqlite3_close(domain_rules_db);
  if (sqlite3_open(dbfile, &domain_rules_db) != SQLITE_OK)
    throw std::runtime_error(sqlite3_errmsg(domain_rules_db));
}

int domain_rules_match(const std::string &domain) {
  if (!domain_rules_enabled)
    return domain_rules_default_rule;

  auto it = domain_rules_cache.find(domain);
  if (it != domain_rules_cache.end())
    return it->second;

  int res = -1;
  char *errmsg;
  std::string stmt = "select rule from data where domain='" + domain + "';";
  if (sqlite3_exec(
        domain_rules_db, stmt.c_str(),
        [](void *res, int argc, char **argv, char **col) -> int {
          *(int *)res = std::stoi(argv[0]);
          return 0;
        },
        &res, &errmsg) != SQLITE_OK) {
    throw std::runtime_error(errmsg);
  }
  if (res < 0) {
    auto pos = domain.find('.');
    if (pos != std::string::npos) {
      std::string subdomain = domain.substr(pos + 1);
      res = domain_rules_match(subdomain);
    }
  }
  if (res < 0)
    res = domain_rules_default_rule;
  domain_rules_cache.insert({domain, res});

  return res;
}

///////////////////////////////////////////////////////////////////////////////
//                                  ip rules                                 //
///////////////////////////////////////////////////////////////////////////////

bool ip_rules_enabled = false;
int ip_rules_default_rule = RULE_PROXY;
std::vector<std::pair<MMDB_s *, int>> ip_rules_dbs;

void ip_rules_set_default_rule(int rule) { ip_rules_default_rule = rule; }

void ip_rules_add_db(const char *dbfile, int rule) {
  int err;
  MMDB_s *mmdb = new MMDB_s;
  ip_rules_enabled = true;
  if ((err = MMDB_open(dbfile, MMDB_MODE_MMAP, mmdb)) != MMDB_SUCCESS) {
    delete mmdb;
    throw std::runtime_error(MMDB_strerror(err));
  }
  ip_rules_dbs.push_back({mmdb, rule});
}

int ip_rules_match(const tcp::endpoint &endpoint) {
  union {
    struct sockaddr a;
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
  } addr;

  if (!ip_rules_enabled)
    return ip_rules_default_rule;

  std::memset(&addr, 0, sizeof(addr));
  if (endpoint.address().is_v4()) {
    addr.v4.sin_family = AF_INET;
    std::memcpy(&addr.v4.sin_addr, &endpoint.address().to_v4().to_bytes()[0], 4);
  } else if (endpoint.address().is_v6()) {
    addr.v6.sin6_family = AF_INET6;
    std::memcpy(&addr.v6.sin6_addr, &endpoint.address().to_v6().to_bytes()[0], 16);
  } else {
    throw std::invalid_argument("match ip rules invalid address family");
  }

  for (auto &db : ip_rules_dbs) {
    int err;
    MMDB_lookup_result_s res;
    res = MMDB_lookup_sockaddr(db.first, &addr.a, &err);
    if (err != MMDB_SUCCESS)
      throw std::runtime_error(MMDB_strerror(err));
    if (res.found_entry)
      return db.second;
  }

  return ip_rules_default_rule;
}

///////////////////////////////////////////////////////////////////////////////
//                                rules match                                //
///////////////////////////////////////////////////////////////////////////////

co_async<int> rules_match(socks5_req &req, bool local_proxy, tcp::socket &socket, int id) {
  int rule = RULE_BLOCK;
  bool is_domain_req = req.atype == ATYPE::domain;

  if (is_domain_req) {
    rule = domain_rules_match(req.domain.first);
    assert(rule == RULE_BLOCK || rule == RULE_PROXY || rule == RULE_DIRECT);
    if (local_proxy && rule == RULE_PROXY)
      rule = RULE_DIRECT;
    if (rule != RULE_DIRECT)
      goto success;
    req.endpoint = *co_await tcp::resolver(socket.get_executor())
                      .async_resolve(req.domain.first, "", asio::use_awaitable);
    req.endpoint.port(req.domain.second);
    req.atype = req.endpoint.address().is_v4() ? ATYPE::v4 : ATYPE::v6;
  }

  rule = ip_rules_match(req.endpoint);
  assert(rule == RULE_BLOCK || rule == RULE_PROXY || rule == RULE_DIRECT);
  if (local_proxy && rule == RULE_PROXY)
    rule = RULE_DIRECT;

success:
  if (req.atype == ATYPE::domain)
    loginfo(id, socket.remote_endpoint(), req.domain, rule);
  else if (is_domain_req)
    loginfo(id, socket.remote_endpoint(), req.endpoint, req.domain, rule);
  else
    loginfo(id, socket.remote_endpoint(), req.endpoint, rule);
  co_return rule;
}
