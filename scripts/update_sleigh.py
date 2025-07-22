#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This script is used to help fetch the latest ghidra stable source
and exact the SLA library of sleigh source code.
"""

from collections.abc import Collection
import os
import re
import sys
import shutil
import argparse

CMAKE_FILE_TEMPLATE = """cmake_minimum_required(VERSION 3.10)

project(sleigh)

set(CMAKE_CXX_STANDARD_REQUIRED on)
set(CMAKE_CXX_STANDARD 17)

# we need to define these to make sure local zlib compiling work
# you can comment the following links to use standard zlib

add_compile_definitions(LOCAL_ZLIB=1 NO_GZIP=1)

# build zlib

aux_source_directory(zlib ZLIB_SRC)
add_library(zlib STATIC ${ZLIB_SRC})
target_include_directories(zlib PUBLIC zlib)

# build sleigh

aux_source_directory(sleigh SLEIGH_SRC)
add_library(sleigh STATIC ${SLEIGH_SRC})
target_include_directories(sleigh PUBLIC zlib PUBLIC sleigh)
target_link_libraries(sleigh PRIVATE zlib)

# build example tool

aux_source_directory(example EXAMPLE_SRC)
add_executable(example ${EXAMPLE_SRC})
target_include_directories(example PUBLIC sleigh)
target_link_libraries(example PRIVATE sleigh PRIVATE zlib)

# build compiler tool

aux_source_directory(compiler COMPILER_SRC)
add_executable(compiler ${COMPILER_SRC})
target_include_directories(compiler PUBLIC sleigh)
target_link_libraries(compiler PRIVATE sleigh PRIVATE zlib)
"""

def info(s):
    sys.stdout.write(f"[+] {s}\n")

def warn(s):
    sys.stderr.write(f"[!] {s}\n")

def die(s):
    warn(s)
    sys.exit(1)
    
class CommandLineParser:
    OUTDIR = "out"
    def __init__(self):
        cli = argparse.ArgumentParser(description="Sleigh extract util")
        cli.add_argument("-g", "--ghidra", help="Ghidra source code folder")
        cli.add_argument("-o", "--outdir", 
                         default=self.OUTDIR, help=f"Output folder (default: {self.OUTDIR})")
        cli.add_argument("-p", "--processors", action="store_true", help="Copy processors data for compilation")
        cli.add_argument("-b", "--build", action="store_true", help="Generate CMakeLists.txt for build")
        self._cli = cli

    def run(self) -> argparse.Namespace:
        opts = self._cli.parse_args()
        if not os.path.isdir(opts.ghidra):
            die(f"invalid ghidra folder: {opts.ghidra}")

        if os.path.exists(opts.outdir):
            shutil.rmtree(opts.outdir)
        os.mkdir(opts.outdir)
        
        return opts

class App:

    def _ghidra_to_decompile_dir(self, ghidra: str) -> str:
        src_dir = os.path.join(ghidra,
                               "Ghidra",
                               "Features",
                               "Decompiler",
                               "src",
                               "decompile")
        return src_dir
        
    def parse_makefile(self, makefile: str) -> dict[str, str]:
        kv = dict()
        with open(makefile) as fp:
            ctx = list()
            for line in fp.readlines():
                s = line.strip()
                if s.startswith("#"):
                    continue

                if s.endswith("\\"):
                    ctx.append(s[:-1])
                else:
                    ctx.append(s)
                    if ctx:
                        d = " ".join(ctx)
                        ctx = list()
                        if "=" in d:
                            k, v = d.split("=", 1)
                            kv[k] = v
            if ctx:
                d = " ".join(ctx)
                if "=" in d:
                    k, v = d.split("=", 1)
                    kv[k] = v
        return kv
    
    def is_balance(self, s: str) -> bool:
        lb = 0
        rb = 0
        for c in s:
            if c == '(':
                lb += 1
            elif c == ')':
                rb += 1
        return lb == rb
    
    def expand_kv(self, k: str, kv: dict[str, str]) -> str:
        v = kv.get(k, "")
        if len(v) == 0:
            return v

        elems = filter(lambda x: len(x)>0, map(lambda x: x.strip(), v.split(" ")))
        ctx = list()
        res = list()
        for elem in elems:
            if ctx:
                ctx.append(elem)
                x = " ".join(ctx)
                if self.is_balance(x):
                    res.append(x)
                    ctx = list()
            else:
                if elem.startswith("$("):
                    if elem.endswith(")"):
                        name = elem[2:-1]
                        if self.is_balance(name):
                            v = self.expand_kv(name, kv)
                            res.append(v)
                            continue
                res.append(elem)
                
        return " ".join(res)

    def get_files(self, value) -> list[str]:
        return list(filter(lambda x: len(x) > 0, map(lambda s: s.strip(), value.split(" "))))
    
    def get_files_by_ext(self, ext: str, names: list[str]) -> list[str]:
        return list(map(lambda name: name + ext, names))

    def get_inline_headers(self, filenames: list[str]) -> set[str]:
        pattern = re.compile(r"^\s*#\s*include\s*\"(\w+\.hh?)\"\s*$")
        res = set()
        for filename in filenames:
            try:
                with open(filename) as fp:
                    for line in fp.readlines():
                        m = pattern.match(line)
                        if m:
                            res.add(m.group(1))
            except:
                warn(f"warning: failed to open file: {filename}")
        return res
    
    def unique(self, l: list[str]) -> list[str]:
        return list(set(l))
    
    def collect_headers(self, src_dir, filenames) -> set[str]:
        files = filenames.copy()
        
        while True:
            hdr_files = self.unique(list(map(lambda name: os.path.join(src_dir, name), files)))
            headers = self.get_inline_headers(hdr_files)
            found = False
            for header in headers:
                if header not in files:
                    # if we found a new header file add it back to files and refind again
                    # this is not effecient but it works
                    files.add(header)
                    found = True

            if not found:
                break
            
        return files
    
    def copy_files(self, outdir: str, srcdir: str, names: list[str]):
        for name in names:
            filename = os.path.join(srcdir, name)
            if os.path.exists(filename):
                dst = os.path.join(outdir, name)
                info(f"copy file {dst}")
                shutil.copyfile(filename, dst)
            else:
                warn(f"warning: skip non-exist file: {name}")
        
    def copy_sleigh_src(self, ghidra_dir: str, outdir: str):
        src_dir = os.path.join(self._ghidra_to_decompile_dir(ghidra_dir), "cpp")
        kv = self.parse_makefile(os.path.join(src_dir, "Makefile"))
        d = kv.copy()
        for k in kv.keys():
            d[k] = self.expand_kv(k, d)
            
        libsla = d.get("LIBSLA_NAMES", "")
        names = self.get_files(libsla)
        src_names = self.get_files_by_ext(".cc", names)
        hdr_names = self.get_files_by_ext(".hh", names)
        
        src_files = self.unique(list(map(lambda name: os.path.join(src_dir, name), src_names)))
        src_headers = self.get_inline_headers(src_files)
        src_headers.update(hdr_names)

        headers = self.collect_headers(src_dir, src_headers)
        src_outdir = os.path.join(outdir, "sleigh")
        os.mkdir(src_outdir)

        self.copy_files(src_outdir, src_dir, src_names)
        self.copy_files(src_outdir, src_dir, list(headers))

    def copy_zlib_src(self, ghidra_dir: str, outdir: str):
        src_dir = os.path.join(self._ghidra_to_decompile_dir(ghidra_dir), "zlib")
        if os.path.exists(src_dir):
            info(f"copy zlib")
            src_outdir = os.path.join(outdir, "zlib")
            shutil.copytree(src_dir, src_outdir)

    def setup_bin(self, ghidra_dir: str, outdir: str, names: list[str], target: str):
        info(f"setup binary {target}")

        ghidra_decompile_dir = self._ghidra_to_decompile_dir(ghidra_dir)
        dest_dir = os.path.join(outdir, target)
        os.mkdir(dest_dir)

        for name in names:
            filename = os.path.join(ghidra_decompile_dir, "cpp", name)
            info(f"copy {name}")
            shutil.copyfile(filename, os.path.join(dest_dir, name))

    def copy_processors(self, ghidra_dir: str, outdir: str):
        processors_dir = os.path.join(ghidra_dir, "Ghidra", "Processors")
        if not os.path.isdir(processors_dir):
            die("cannot find processors directory")

        dest_dir = os.path.join(outdir, "Processors")
        os.mkdir(dest_dir)

        for arch in os.listdir(processors_dir):
            arch_dir = os.path.join(processors_dir, arch)
            if os.path.isdir(arch_dir):
                target_dir = os.path.join(dest_dir, arch)
                os.mkdir(target_dir)
                info(f"copy processor data for {arch}")
                shutil.copytree(
                    os.path.join(arch_dir, "data"), 
                    os.path.join(target_dir, "data"))


    def run(self):
        opts = CommandLineParser().run()
        self.copy_sleigh_src(opts.ghidra, opts.outdir)
        self.copy_zlib_src(opts.ghidra, opts.outdir)
        # FIXME: hardcode -> Makefile
        self.setup_bin(opts.ghidra, opts.outdir, ["sleighexample.cc"], "example")

        # FIXME: hardcode -> Makefile
        self.setup_bin(opts.ghidra, opts.outdir, 
                       ["slgh_compile.hh", "slgh_compile.cc", "slghparse.hh", "slghparse.cc", "slghscan.cc"], 
                       "compiler")
        
        # copy processors files
        if opts.processors:
            self.copy_processors(opts.ghidra, opts.outdir)

        # generate build file
        if opts.build:
            info("generate build file")
            with open(os.path.join(opts.outdir, "CMakeLists.txt"), "w") as fp:
                fp.write(CMAKE_FILE_TEMPLATE)
        
def main():
    App().run()
    
if __name__ == "__main__":
    main()
    
