"""
Unit Test for CPOR scheme

:Authors: 
:Date:    
"""
import unittest, subprocess, tempfile
import re, glob, os, logging, sys, time
from optparse import OptionParser
from subprocess import PIPE

PDP = {"blocksize":4096, "challenges":512} # default params
TESTFILES = "/tmp/" # location of files for testing
BIN = os.path.dirname(os.path.abspath(__file__))+"/../../schemes/cpor_pub_sw05.py"

class WrapperTest(unittest.TestCase):

    def subproc(self, *args):
        return subprocess.Popen(*args,
                shell=False, close_fds=True,
                stdout=PIPE, stdin=None, stderr=PIPE)

    def fillFile(self, len=100):
        fd, path = tempfile.mkstemp(dir=TESTFILES)
        self.path = path
        os.write(fd, os.urandom(len))
        os.close(fd)

    def emptyFile(self):
        os.unlink(self.path)
        if os.path.exists(self.path):
            os.unlink(self.path)

    def output_test(self, cargs, pargs, **kwargs):
        prover_args = [BIN, "-p"] + pargs
        chall_args = [BIN, "-c"] + cargs
        
        args = ''.join([x+' ' for x in prover_args])
        print ("=====> Running: %s" % (args))
        p = self.subproc(prover_args)
        time.sleep(1)

        args = ''.join([x+' ' for x in chall_args])
        print ("=====> Running: %s" % (args))
        q = self.subproc(chall_args)

        (out1, err1) = p.communicate()
        (out2, err2) = q.communicate()
        p.wait()
        q.wait()

        print(out1, out2, err1, err2)

        self.assertEqual(err2, b'',
            "expected empty stderr for challenger, got:\n%s" % (err2))
        self.assertEqual(err1, b'',
            "expected empty stderr for prover, got:\n%s" % (err1))
        self.assertEqual(p.returncode, 0,
            "expected 0 for prover returncode, got %s" % (p.returncode))
        self.assertEqual(q.returncode, 0,
            "expected 0 for chall returncode, got %s" % (q.returncode))

        if 'audits' in kwargs:
            num = str(out2).count("3 =>")
            self.assertEquals(kwargs['audits'], num,
                "audited %d times instead of %d" % (num, kwargs['audits']))

        fsize = os.path.getsize(kwargs['filename'])
        bsize = PDP['blocksize']
        if 'blocksize' in kwargs:
            bsize = kwargs['blocksize']
        total_blocks = int(round(float(fsize) / bsize))

        if 'chal_blocks' in kwargs:
            num_chals = kwargs['chal_blocks']
            if total_blocks < num_chals:
                num_chals = total_blocks
            s = "Challenging " + str(num_chals) +" blocks:"
            self.assertNotEqual(str(out2).count(s), 0,
                "Expected %s in the output %s" % (s, str(out2)))

        if 'blocksize' in kwargs:
            s = "Blocksize: " + str(kwargs['blocksize'])
            self.assertNotEqual(str(out2).count(s), 0,
                "Expected %s in the output %s" % (s, str(out2)))


class TestBasic(WrapperTest):
    
    def test_fraction_blocks(self):
        params = {}
        blocksize = PDP['blocksize']
        for num in [0.5, 1, 2, 2.5, 3.5]:
            self.fillFile(int(num*blocksize))
            cargs = ["-f", self.path, "-l", "1", "-b", str(blocksize)]
            params['filename'] = self.path
            self.output_test(cargs, [], **params)
            self.emptyFile()
                
    def test_many_blocks(self):
        params = {}
        blocksize = PDP['blocksize']
        challenges = PDP['challenges']
        for num in [0.5*challenges, 2*challenges, 5*challenges]:
            self.fillFile(int(num*blocksize))
            cargs = ["-f", self.path, "-l", "1", "-v"]
            params['filename'] = self.path
            params['blocksize'] = blocksize
            self.output_test(cargs, [], **params)
            self.emptyFile()
        
    def test_block_size(self):
        params = {}        
        for num in [1024, 2048, 4096]:
            self.fillFile(int(num*PDP['challenges']))
            cargs = ["-f", self.path, "-l", "1", "-b", str(num), "-v"]
            params['filename'] = self.path
            params['blocksize'] = num
            self.output_test(cargs, [], **params)
            self.emptyFile()   
          
    def test_num_of_challenge(self):
        params = {}        
        for num in [300, 460, 500]:
            self.fillFile(int(num*PDP['blocksize']))
            cargs = ["-f", self.path, "-l", "1", "-n", str(num), "-v"]
            params['filename'] = self.path
            params['chal_blocks'] = num
            self.output_test(cargs, [], **params)
            self.emptyFile()   
                       
    def test_number_of_audits(self):
        params = {}        
        for num in [1, 2, 5, 7]:
            self.fillFile(int(PDP['blocksize']))
            cargs = ["-f", self.path, "-l", str(num), "-v"]
            params['filename'] = self.path
            params['audits'] = num
            self.output_test(cargs, [], **params)
            self.emptyFile() 
                         
###############################################################################
#
# Main
#
if __name__=="__main__":
    unittest.main()
    exit(0);

