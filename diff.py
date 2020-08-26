#!/usr/bin/env python3

import sys
import subprocess
import string
import re

from collections import defaultdict



def canonical_arg(arg):
  try:
    int(arg)
    return 'IMM'
  except:
    if arg in ',()': return arg
    if arg.startswith('*'): arg = arg[1:]
    if arg.startswith('<'): return 'ADDR'
    if arg.startswith('$'): return 'IMM'
    if arg.startswith('-'): return 'IMM'
    if arg.startswith('0x'): return 'IMM'
    if arg.startswith('%r'): return 'REG_64'
    if arg.startswith('%e'): return 'REG_32'
    if arg.startswith('%x'): return 'REG_XMM'
    if arg.startswith('%') and arg[-1] in 'lh': return 'REG_8'
    if arg.startswith('%'): return 'REG_16'
    return arg


def parse_file(obj):
  lines = subprocess.check_output([
    'objdump', '-d', obj, '--no-show-raw-insn', '--no-addresses'
  ]).split(b'\n\n')

  hist = defaultdict(lambda: defaultdict(int))
  for line in lines:
    content = []
    for l in line.split(b'\n'):
      l = l.decode('utf-8').strip()
      if not l: continue
      if 'Disassembly' in l: continue
      content.append(l)

    if not content: continue
    addr = content[0]
    func = addr[1:-2]
    if not func.startswith('caml') or func[4] == '_': continue
    for l in content[1:]:
      l = l.split('#')[0]
      op, *args = [t for t in l.replace('\t',' ').split(' ') if t]
      if args:
        assert(len(args) == 1)
        args = [canonical_arg(arg) for arg in re.split('(,|\\(|\\))', args[0])]
      else:
        args = []
      inst = '{} {}'.format(op, ''.join(args)).strip()
      hist[func][inst] += 1
  return hist


def diff(obj_ml, obj_llir):
  hist_ml = parse_file(obj_ml)
  hist_llir = parse_file(obj_llir)

  insts_ml = defaultdict(int)
  insts_llir = defaultdict(int)

  for func, syms in hist_ml.items():
    if func not in hist_llir: continue
    for inst, val in syms.items():
      insts_ml[inst] += val
    for inst, val in hist_llir[func].items():
      insts_llir[inst] += val

  keys = set(insts_ml.keys()) | set(insts_llir.keys())
  comparison = []
  for key in keys:
    count_ml = insts_ml.get(key, 0)
    count_llir = insts_llir.get(key, 0)
    comparison.append((key, count_ml, count_llir))
  comparison.sort(key=lambda v: v[1])
  total_ml = 0
  total_llir = 0
  print('{} {} {}'.format('INSTRUCTION'.ljust(40), 'OCAML'.rjust(7), 'LLIR'.rjust(7)))
  for key, ml, llir in comparison:
    print('{} {:7} {:7}'.format(key.ljust(40), ml, llir))
    total_ml += ml
    total_llir += llir
  print('{} {:7} {:7}'.format('TOTAL: '.ljust(40), total_ml, total_llir))

if __name__ == '__main__':
  diff(sys.argv[1], sys.argv[2])
