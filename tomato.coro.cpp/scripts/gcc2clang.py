#!/usr/bin/env python3
'''
Generates clang++ compile_commands.json for clangd, which doesn't recognize g++ flags.
'''

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--infile', default='build/compile_commands.json')
parser.add_argument('-o', '--outfile', default='compile_commands.json')
args = parser.parse_args()

infile = args.infile
outfile = args.outfile

data = open(infile).read()
data = data.replace('g++', 'clang++')
data = data.replace('-std=c++20', '-std=c++20 -stdlib=libc++')
data = data.replace('-fcoroutines', '-fcoroutines-ts')

print(data, file=open(outfile, 'w'))
