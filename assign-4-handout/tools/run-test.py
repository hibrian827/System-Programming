#!/usr/bin/python

import sys
import os
import subprocess
import fileinput
import re
import filecmp
from difflib import Differ

DRV_PATH = "./tools/sdriver.pl"
TSHARGS = "-p"

class bcolors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


def sanitize(before_fn, after_fn):
    # Replace all PIDs.
    # (1010) -> (PID 1)
    # (1013) -> (PID 2)
    # (1010) -> (PID 1)

    pids = []
    lines = []

    lines = open(before_fn, "r").read().split("\n")

    # collect all pids
    for line in lines:
        ms = re.findall( r'\([\d]*\)', line)
        for m in ms:
            pid = int(m[1:-1])
            pids.append(pid)

    output = "\n".join(lines)

    # replace pids all together
    for vid, pid in enumerate(pids):
        output = output.replace("(%d)" % pid, "(PID %d)" % vid)


    # replace tsh_ref into tsh all together
    output = output.replace("tsh_ref", "tsh")

    open(after_fn, "w").write(output)
    return

def log(msg):
    print("%s" % (msg))
    return

def decode_utf8(s):
    if type(s) == bytes:
        try:
            out = s.decode("utf-8")
        except:
            out = str(s)
        return out
    return s

class RunError(Exception):
    def __init__(self, output):
        self.output = output

def mkdir(dn):
    if not os.path.exists(dn):
        os.mkdir(dn)

def run_cmdstr(cmdstr, cwd=None):
    # log(cmdstr)
    cmds = cmdstr.split()
    try:
        output = subprocess.check_output(cmds,
                                         stderr=subprocess.STDOUT,
                                         timeout=60,
                                         cwd=cwd)

    except subprocess.CalledProcessError as e:
        log("Error cmdstr (CalledProcessError) [%s]" % cmdstr)
        log("  e.returncode: %s" % e.returncode)
        raise RunError(decode_utf8(e.output))
    except subprocess.TimeoutExpired:
        log("Error cmdstr (Timeout) [%s]" % cmdstr)
        raise RunError("Timeout")
    except:
        raise RunError("Unknown Exception")
    return decode_utf8(output)

def run_driver(test_name, sh_path, log_fn):
    cmdstr  = f"{DRV_PATH}"
    cmdstr += f" -t ./traces/{test_name}.trace "
    cmdstr += f" -s {sh_path} -a {TSHARGS}"

    output = run_cmdstr(cmdstr)
    open(log_fn, "w").write(output)
    return

def run_test(test_name):
    mkdir("output-tests")

    ref_log_fn = f"output-tests/{test_name}.log.ref"
    san_ref_fn = ref_log_fn + ".san"
    cur_log_fn = f"output-tests/{test_name}.log.cur"
    san_cur_fn = cur_log_fn + ".san"

    print(f"[{test_name}]: Running reference tsh")
    run_driver(test_name, "./tsh_ref", ref_log_fn)

    print(f"[{test_name}]: Running your tsh")
    run_driver(test_name, "./tsh", cur_log_fn)
    sanitize(ref_log_fn, san_ref_fn)
    sanitize(cur_log_fn, san_cur_fn)

    if filecmp.cmp(san_ref_fn, san_cur_fn):
        print(f"[{test_name}]: {bcolors.OKGREEN}PASS{bcolors.ENDC}")
        return True
    print(f"[{test_name}]: {bcolors.FAIL}FAIL{bcolors.ENDC}")

    # differ = Differ()
    # diff_lines = differ.compare(open(san_ref_fn, "r").read(),
    #                             open(san_cur_fn, "r").read())

    # for line in diff_lines:
    #     print(line)

    return False

if __name__ == "__main__":

    test_names = sys.argv[1:]

    for test_name in test_names:
        run_test(test_name)


