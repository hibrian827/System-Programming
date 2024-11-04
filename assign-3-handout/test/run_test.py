#!/usr/bin/env python3
import os
import subprocess

SNUDBG = "../src/snudbg"

def log(msg):
    print("[*] " + msg)
    return

class TestFailException(Exception):
    def __init__(self, tester, estr):
        self.estr = estr
        self.tester = tester

    def __str__(self):
        s = ""
        s += '[-] TestFailException: [%s][%s]\n' % (self.tester.bin_fn,
                                                    self.tester.input_fn)
        s += '\t Fail reason: [%s]' % (self.estr)
        return s

    def __repr__(self):
        return str(type(self))

class SNUDbgTester:
    def __init__(self, bin_fn):
        self.bin_fn = bin_fn
        self.cmds = [SNUDBG, self.bin_fn]
        self.p = subprocess.Popen(self.cmds,
                                  stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE,
                                  encoding='ascii')

    def run(self, input_fn, expected):
        self.input_fn = input_fn
        instr = open(input_fn, "r").read()
        outstr = self.p.communicate(input=instr)[0]
        # print(outstr)

        last_index = 0
        for estr in expected:
            index = outstr.find(estr)
            if index == -1:
                raise TestFailException(self, "Unable to find: %s" % estr)
            elif index <= last_index:
                raise TestFailException(self, "Incorrect order: %s" % estr)

            last_index = index
        return outstr

def test_rand_mem_write():
    expected = []
    expected += ["555555558010 34 12 00 00"]
    expected += ["rip=555555555256 child_status=1407"]
    expected += ["555555558010 dd cc bb aa"]
    expected += ["rip=5555555551ca child_status=1407"]

    tester = SNUDbgTester("./prebuilt/rand")
    outstr = tester.run("./prebuilt/rand.mem-write.input", expected)
    return

def test_rand_set_reg():
    expected = []
    expected += ["rip=55555555521e child_status=1407"]
    expected += ["rip=0x55555555521d"]
    expected += ["eflags=0x242"]
    expected += ["rip=5555555551ca child_status=1407"]

    tester = SNUDbgTester("./prebuilt/rand")
    outstr = tester.run("./prebuilt/rand.set-reg.input", expected)
    return

def test_array_check():
    expected = []
    expected += ["555555558240 00"]
    expected += ["555555558040 00 00 00"]
    expected += ["555555558240 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"]
    expected += ["555555558250 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"]
    expected += ["555555558140 00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00"]
    expected += ["555555558230 3c 00 00 00 3d 00 00 00 3e 00 00 00 3f 00 00 00"]

    tester = SNUDbgTester("./prebuilt/array")
    outstr = tester.run("./prebuilt/array.check.input", expected)
    return

def run_test(test_fn):
    try:
        test_fn()
    except TestFailException as e:
        print(e)
        print("[-] FAIL: %s" % test_fn.__name__)
        return

    print("[+] PASS: %s" % test_fn.__name__)
    return

if __name__ == "__main__":

    tests = [test_rand_mem_write, test_rand_set_reg, test_array_check]

    for t in tests:
        run_test(t)

    # t.run_input_file("./prebuilt/rand.set-reg.input")

    # t = SNUDbgTest("./prebuilt/array")
    # t.run_input_file("./prebuilt/array.check.input")


