#!/usr/bin/python3
"""
CPOR with Private Verificability

| From paper: Compact Proofs of Retrievavility
| Published in: ASIACRYPT 2005

:Authors: 
:Date:    
"""
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.core.math.pairing import hashPair as sha1
from charm.core.math.integer import integer,random,randomBits
from charm.core.engine.protocol import *
from charm.toolbox.symcrypto import MessageAuthenticator
from charm.toolbox.RandSubset import RandSubset
from charm.toolbox.POR import PORbase
import sys, math, argparse


class CPORpriv(PORbase):
    def __init__(self, common_input=None):
        PORbase.__init__(self, common_input)    

    def set_attributes(self, args):
        """ 
        Implements :py:func:`POR.PORbase.set_attributes()`
        """
        return None

    def keyGen(self):
        """ 
        Implements :py:func:`POR.PORbase.keyGen()`
        """
	return None
    
    def tag(self, filename, pk, sk):
        """ 
        Implements :py:func:`POR.PORbase.tag()`
        """
        return None 

    def generateChallenge(self, filestate, pk, sk):  
        """ 
        Implements :py:func:`POR.PORbase.generateChallenge()`
        """
        return None
    
    def generateProof(self, challenge, pk, data):  
        """  
        Implements :py:func:`POR.PORbase.generateProof()`
        """
        return None
    
    def verifyProof(self, proof, challenge, chalData, pk, sk):
        """
        Implements :py:func:`POR.PORbase.verifyProof()`
        """
        return True
   
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CPOR-Priv Scheme")
    parser.add_argument("-v", "--verbose", 
        action="store_true", default=False, 
        dest="verbose", help="Verbose output")
    parser.add_argument("-f", "--filename",
        action="store", dest="file_name", 
        help="Path to file, to store and audit.")
    parser.add_argument("-c", "--challenger",
        action="store_true", default=False, 
        dest="challenger", help="Act as challenger.")
    parser.add_argument("-p", "--prover",
        action="store_true", default=False, 
        dest="prover", help="Act as prover.")

    parser.add_argument("-l", "--num_audits",
        action="store", type=int, default=3, 
        dest="num_of_audits", help="Number of times to audit (default, 3)")
    parser.add_argument("-b", "--block_size",
        action="store", type=int, default=4096, 
        dest="block_size", help="Block size in bytes (default, 4096)")
    args = parser.parse_args()

    pdp = CPORpriv(None)
    pdp.start(args)
