#!/usr/bin/env python3

import argparse
import struct
from typing import Optional

import cxxfilt
from colorama import Fore, Style

import util.elf
from util import utils


def find_vtable(symtab, class_name: str) -> Optional[str]:
    name_offset = len("vtable for ")
    for sym in util.elf.iter_symbols(symtab):
        if not sym.name.startswith("_ZTV"):
            continue
        if cxxfilt.demangle(sym.name)[name_offset:] == class_name:
            return sym.name
    return None


def bold(s) -> str:
    return Style.BRIGHT + str(s) + Style.NORMAL


def dump_table(name: str) -> None:
    try:
        symbols = util.elf.build_addr_to_symbol_table(util.elf.my_symtab)
        decomp_symbols = {}

        offset, size = util.elf.get_symbol_file_offset_and_size(util.elf.base_elf, util.elf.my_symtab, name)
        util.elf.base_elf.stream.seek(offset)
        vtable_bytes = util.elf.base_elf.stream.read(size)

        if not vtable_bytes:
            utils.fail(
                "empty vtable; has the key function been implemented? (https://lld.llvm.org/missingkeyfunction.html)")

        print(f".section .data.rel.ro\n\t.globl {name}\n\n{name}:")
        #print(f"{Fore.YELLOW}{Style.BRIGHT}vtable @ 0x0{Style.RESET_ALL}")
        name_bkp = name
        assert size % 8 == 0
        for i in range(size // 8):
            word: int = struct.unpack_from("<Q", vtable_bytes, 8 * i)[0]
            name = symbols.get(word, None)
            if word == 0:
                print(f"\t.quad {word}")
            elif name is not None:
                demangled_name: str = cxxfilt.demangle(name)
                color = Fore.GREEN if name in decomp_symbols else Fore.BLUE
                #print(f"{color}{bold(demangled_name)}{Style.RESET_ALL}")
                print(f"\t.quad {name}")
            elif word & (1 << 63):
                offset = -struct.unpack_from("<q", vtable_bytes, 8 * i)[0]
                print(f"\t.quad {word:#x}")
                #print(f"{Fore.YELLOW}{Style.BRIGHT}vtable @ {offset:#x}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}unknown data: {word:016x}{Style.RESET_ALL}")

    except KeyError:
        utils.fail("could not find symbol")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("symbol_name", help="Name of the vtable symbol (_ZTV...) or class name")
    args = parser.parse_args()

    symbol_name: str = args.symbol_name

    if not symbol_name.startswith("_ZTV"):
        symbol_name = find_vtable(util.elf.my_symtab, args.symbol_name)

    dump_table(symbol_name)


if __name__ == "__main__":
    main()
