#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import argparse
import subprocess

class CommandLineParser:
    OUTDIR = "out"

    def run(self):
        pr = argparse.ArgumentParser(description="Fetch latest ghidra stable branch source code")
        pr.add_argument("-o", "--out", default=self.OUTDIR, help=f"output folder (default: {self.OUTDIR})")
        opts = pr.parse_args()
        if os.path.exists(opts.out):
            shutil.rmtree(opts.out)
        os.mkdir(opts.out)
        return opts.out


class App:
    GHIDRA_GIT_LINK = "https://github.com/NationalSecurityAgency/ghidra.git"
    
    def __init__(self):
        self.outdir = CommandLineParser().run()

    def capture_out(self, *cmds):
        out = subprocess.check_output(cmds, encoding="utf-8")
        return out.strip()
        
    def exec_cmd(self, *cmds):
        subprocess.run(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        
    def fetch_source_code(self, outdir):
        current_dir = os.getcwd()
        os.chdir(outdir)
        try:
            print("[!] Fetching ghidra source code from remote, please be waiting ...")
            self.exec_cmd("git", "clone", self.GHIDRA_GIT_LINK)
            os.chdir("ghidra")
            latest_tag = self.capture_out("git", "describe", "--abbrev=0", "--tags")
            print(f"[!] Retrieve latest stable release tag: {latest_tag}")
            print(f"[!] Switch to {latest_tag}")
            self.exec_cmd("git", "checkout", latest_tag)
            print("[!] Done")
        except:
            print("[x] Something error!")
        finally:
            os.chdir(current_dir)
            
    def run(self):
        self.fetch_source_code(self.outdir)
        
if __name__ == "__main__":
    App().run()
    
