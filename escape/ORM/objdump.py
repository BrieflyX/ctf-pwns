#!/usr/bin/env python
# coding: utf-8

import struct
import string

class Segment:
    def __init__(self, addr, length, filelen, flag, data):
        self.addr = addr
        self.length = length
        self.filelen = filelen
        self.flag = flag
        self.data = data

segs = []
symbols = {0x800000009A: 'write', 0x8000000001: 'read', 0x80000003B6: 'strlen', 0x8000000281: 'atoi',
           0x8080808080808556: 'main_loop', 0x808080808080805B: 'add_project', 0x8080808080808382: 'migrate_project', 0x80808080808081F0: 'show_project', 0x8080808080808013: 'find_project'}

oper64 = {0x0: 'nop', 0x1: 'push', 0x2: 'pop', 0x3: 'neg',
          0x4: 'add', 0x5: 'sub', 0x6: 'mul', 0x7: 'div', 0x8: 'mod', 0x9: 'lshl', 0xa: 'ashl', 0xb: 'shr',
          0xb: 'shr', 0xc: 'and', 0xd: 'or', 0xe: 'xor',
          0xf: 'equ', 0x10: 'neq', 0x11: 'gtu', 0x12: 'gteu', 0x13: 'gt', 0x14: 'gte',
          0x15: 'b', 0x16: 'bnez', 0x17: 'beqz', 0x18: 'getsp', 0x19: 'int',
          0x1a: 'call', 0x1b: 'st', 0x1c: 'st', 0x1d: 'ld', 0x1e: 'hlt', 0x1f: 'hlt'}


def read_mem(addr, size):
    for s in segs:
        if addr >= s.addr and addr < s.addr + s.length:
            offset = addr - s.addr
            if offset + size <= len(s.data):
                return s.data[offset:offset+size]
    return None

def probe_string(addr):
    s = ''
    i = 0
    while True:
        ret = read_mem(addr+i, 1)
        if ret == None or ret not in string.printable:
            return s
        s += ret
        i += 1

def symbol(addr):
    if addr in symbols.keys():
        return symbols[addr]
    else:
        return '0x{:X}'.format(addr)

def mem_suffix(opc):
    if opc & 3 == 0:
        return 'b'      # byte
    elif opc & 3 == 1:
        return 'w'      # word
    elif opc & 3 == 2:
        return 'd'      # dword
    else:
        return 'q'      # qword


def disasm64(code, addr):
    pc = 0
    while pc < len(code):
        opc = ord(code[pc])
        op = opc >> 3
        dst = 'L' if ((opc >> 2) & 1 == 0) else 'R'
        src = opc & 3
        if opc & 3 == 0:
            src = 'I'   # Immediate
        elif opc & 3 == 1:
            src = 'L'   # Left stack
        elif opc & 3 == 2:
            src = 'R'   # Right stack
        else:
            src = 'V'   # Value (result)
        
        imm = None
        inst = ''
        if addr+pc in symbols.keys():
            inst += '; {}\n'.format(symbols[addr+pc])
        inst += '{:08X}:\t'.format(addr+pc) + oper64[op]
        pc += 1

        if (op == 0x1 or op == 0x16 or op == 0x17) and src == 'I':
            imm = struct.unpack('<Q', code[pc:pc+8])[0]
            pc += 8
            inst += ' {} {}'.format(dst, symbol(imm))
        elif op == 0x2:
            # pop
            inst += ' {}'.format(dst)
        elif op == 0x3:
            # neg / inv
            if opc & 3 == 1:
                inst = inst.replace('neg', 'inv')
            inst += ' {}'.format(dst)
        elif op == 0x15:
            # branch
            if src == 'I':
                imm = struct.unpack('<Q', code[pc:pc+8])[0]
                pc += 8
                inst += ' ' + symbol(imm)
            else:
                inst += ' {}'.format(src)
        elif op == 0x1a:
            # call
            if (opc >> 2) & 1 == 0:
                if src == 'I':
                    imm = struct.unpack('<Q', code[pc:pc+8])[0]
                    pc += 8
                    inst += ' ' + symbol(imm)
                else:
                    inst += ' {}'.format(src)
            else:
            # ret
                inst = inst.replace('call', 'ret') + ' {}'.format(src)
                # possible function boundary
                inst += '\n'
        elif op == 0x1b:
            # st imm
            imm = struct.unpack('<Q', code[pc:pc+8])[0]
            pc += 8
            inst += '{} {} {}'.format(mem_suffix(opc), dst, symbol(imm))
        elif op == 0x1c:
            # st val
            inst += '{} {} V'.format(mem_suffix(opc), dst)
        elif op == 0x1d:
            # ld
            inst += '{} {}'.format(mem_suffix(opc), dst)
        else:
            inst += ' {} {}'.format(dst, src)

        if imm:
            possible_str = probe_string(imm)
            if possible_str:
                inst += '\t; {}'.format(repr(possible_str[:32]))
            else:
                if imm < 0x100 and imm >= 0 and chr(imm) in string.printable:
                    inst += '\t; {}'.format(repr(chr(imm)))

        print(inst)


def load64seg(segs, data):
    addr, length, filelen, flag = struct.unpack('<QQII', data[:0x18])
    seg_data = data[0x18:0x18+filelen]
    print('[+] Segment addr: {:#x}, length: {:#x}, filelen: {:#x}, flag: {}'.format(addr, length, filelen, flag))
    segs.append(Segment(addr, length, filelen, flag, seg_data))
    return filelen+0x18

def readelf(filename):
    global segs
    data = open(filename, 'rb').read()
    magic, wordlen, entry, stacksize, segnum = struct.unpack('<IIQII', data[:0x18])
    pos = 0x18
    print('[+] Wordlen: {}, Entry: {:#x}, Stacksize: {:#x}, Segnum: {}'.format(wordlen, entry, stacksize, segnum))
    if wordlen == 8:
        for i in range(segnum):
            pos += load64seg(segs, data[pos:])
    else:
        print('[*] 32-bit not supported')

def main():
    readelf('./chal.ormb')
    print('[*] Dissasemble executable segment ...')
    for s in segs:
        if s.flag == 4:
            disasm64(s.data, s.addr)

if __name__ == '__main__':
    main()