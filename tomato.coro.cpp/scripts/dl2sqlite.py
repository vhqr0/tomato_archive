#!/usr/bin/env python3
'''
Convert https://github.com/v2fly/domain-list-community data into a sqlite3 database file.
The four match type: domain, full, keyword and regexp, only the first two are supported.
Multi-tags syntax was not support. (So far it doesn't seem to be used.)
'''

import sqlite3
import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true')
parser.add_argument('--datadir', default='data')
parser.add_argument('--dbfile', default='dl.db')
args = parser.parse_args()

verbose = args.verbose
datadir = args.datadir
dbfile = args.dbfile

rule_block = 1
rule_proxy = 2
rule_direct = 3

tag2rule = {
    'ads': rule_block,
    '!cn': rule_proxy,
    'cn': rule_direct,
}

rule_re = re.compile(r'^((\w+):)?([^ #]+)( @([^ #]+))?')

conn = sqlite3.connect(dbfile)
cur = conn.cursor()

try:
    cur.execute('''
    create table if not exists data (
    domain text not null primary key,
    rule integer not null
    )
    ''')
except:
    pass


def load_rule(rules_file, default_tag):
    for line in open(f'{datadir}/{rules_file}'):
        res = rule_re.match(line[:-1])
        if res is None:
            continue
        cmd = res[2] or 'domain'
        tgt = res[3]
        tag = res[5] or default_tag
        rule = tag2rule[tag]
        if verbose:
            print(cmd, tgt, tag, rule)
        if cmd in ('domain', 'full'):
            cur.execute('replace into data values (?, ?)', (tgt, rule))
        elif cmd == 'include':
            load_rule(tgt, default_tag)


load_rule('cn', 'cn')
load_rule('geolocation-!cn', '!cn')

conn.commit()
