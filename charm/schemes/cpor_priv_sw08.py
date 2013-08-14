#!/usr/bin/python3
"""
CPOR with Private Verificability

| From paper: Compact Proofs of Retrievavility
| Published in: ASIACRYPT 2008

:Authors: Mark Gondree and Michael O'Neil 
:Date: 07/08/2013
""" 
from charm.toolbox.securerandom import OpenSSLRand
from charm.core.math.integer import integer,randomBits,randomPrime 
from charm.core.math.integer import random as charm_random
from charm.core.engine.protocol import * 
from charm.toolbox.RandSubset import RandSubset 
from charm.toolbox.POR import PORbase 
from charm.core.crypto.cryptobase import selectPRF,AES,MODE_ECB
from charm.toolbox.paddingschemes import PKCS7Padding
import argparse

def int2bytes(v):
    v, r = divmod(v, 256)
    yield r
    if v == 0:
        raise StopIteration
    for r in int2bytes(v):
        yield r

def PRF(prf, val, len):
    """Implements a PRF g, where :math:`$g: {0,1}^* \\times K -> \mathbb{Z}_p$`, 
    implemented using an underlying PRF f.

    :param prf: A keyed PRF function :math:`$f: {0,1}^* \\times K -> {0,1}^*$`
    :param val: The input to the PRF
    :param len: The byte length of the prime p
    :returns: The output PRF(val), as an element of Z_p 
    """
    padding = PKCS7Padding(block_size = 16)
    byte_val = bytes(int2bytes(int(val)))
    ctxt = prf.encrypt(padding.encode(byte_val))
    elem = ctxt[:int(len)]  # truncated to be an element of Z_p
    return int.from_bytes(elem, byteorder='big')

class CPORpriv (PORbase):
    def __init__(self, common_input = None):
        # key length is in bytes
        self.enc_key_len = 128
        self.mac_key_len = 128
        self.prf_key_len = 32
        self.block_size = 4096
        self.lambda_size = 80  # "typically, \lambda = 80"
        # num chal blocks is \ell, "a conservative choice for \ell is \lambda"
        self.num_challenge_blocks = self.lambda_size
        self.prime_len = (self.lambda_size) / 8 # in bytes
        self.sector_size = (self.lambda_size - 1) / 8  # sectors live in Z_p
        self.prime = randomPrime(self.lambda_size, 1)
        PORbase.__init__(self, common_input)

    def set_attributes(self, args):
        """ 
        Implements :py:func:`POR.PORbase.set_attributes()`
        """ 
        if hasattr(args, 'mac_length'):
            self.mac_key_len = args.mac_length 
        if hasattr(args, 'enc_length'):
            self.enc_key_len = args.enc_length 
        if hasattr(args, 'prf_length'):
            self.prf_key_len = args.prf_length
        if hasattr(args, 'block_size'):
            self.block_size = args.block_size
        if hasattr(args, 'num_chal_blocks'):
            self.num_challenge_blocks = args.num_chal_blocks
        return None 

    def keyGen(self):
        """ Chooses a random symmetric encryption key, and MAC key. No public key.
        We actually never use these, because they are only for stateless clients.
        We hold state, to simplify the challenger side of the protocol.
    
        Implements :py:func:`POR.PORbase.keyGen()`
        """ 
        print("Generating Keys...") 
        pk, sk = dict(), dict()
        sk["kmac"] = OpenSSLRand().getRandomBytes(self.mac_key_len)
        sk["kenc"] = OpenSSLRand().getRandomBytes(self.enc_key_len)
        return (pk, sk) 
    
    def tag (self, filename, pk, sk):
        """ | Breaks the file into sectors and blocks which are used to create other
        | variables. We do not implement erasure code, or the encryption and MAC functions
        | on the tag, or even generate the tag, for simplicity reasons, as we are also 
        | holding state to ensure it is a sigma protocol.
        | :math:`$k_{prf} \\stackrel{R}{\\gets} K_{prf}$`
        | 
        | :math:`$\\alpha_1 \\text{...,} \\alpha_s \\stackrel{R}{\\gets} \\mathbb{Z}_p$`
        | Sigma calculation formula:
        | :math:`$\\sigma_i \\gets f_{k{prf}}(i) + \\sum_{j=1}^s \\alpha_j m_{ij}$`
        | Implements :py:func:`POR.PORbase.tag()`
        """

        print("Blocksize:", self.block_size)
        # the number of sectors in a block
        num_sectors = int(self.block_size / self.sector_size)
        if (self.block_size % self.sector_size is not 0):
            num_sectors += 1
    
        # read in the original file, transform and get length
        with open(filename, 'rb') as f:
            origm = f.read()
    
        #TODO: this is where we would transform via erasure-code in future
        mprime = origm
        mprime_filename = filename
        mprime_len = len(mprime)
    
        # Determining the number of blocks in the file
        num_blocks = int(mprime_len / self.block_size)
        if (mprime_len % self.block_size is not 0):
            num_blocks += 1 
    
        print("Reading blocks and parsing into sectors...")
        m = [[] for i in range(int(num_blocks))]
        with open(mprime_filename, "rb") as f:
            block = f.read(self.block_size)
            i = 0
            while block:
                # parse out the sectors
                sectors = bytearray(block) 
                for j in range(int(num_sectors)):
                    jstart = j * self.sector_size 
                    jend = jstart + min(self.sector_size - 1, len (sectors) - jstart) 
                    m[i].append(bytes(sectors[int(jstart):int(jend)]))
                block = f.read(self.block_size)
                i = i + 1
        
        # For a stateless verifier, we can store here E(kenc; <kprf, alpha>) and MAC(kmac; <num_blocks, ctx>)
        # and store these with the prover;
    
        # generating Pseudo Random Function key
        kprf = OpenSSLRand().getRandomBytes(self.prf_key_len)
        prf = selectPRF(AES,(kprf, MODE_ECB))
    
        # generating alphas
        # a list of random coefficients in Zp, |alpha| = num_sectors
        alpha = [int(integer(charm_random(self.prime))) for i in range(num_sectors)]
    
        # generate the sigmas
        sigmas =[]
        for i in range(num_blocks):
            am = [alpha[j] * int.from_bytes(m[i][j], byteorder='big') for j in range(len(m[i]))]
            fkprf = PRF(prf, (i+1), self.prime_len)
            s = fkprf + sum(am) 
            sigmas.append(s) 
        
        filestate, data = {}, {}
        filestate["num_blocks"] = num_blocks
        filestate["kprf"] = kprf 
        filestate["alpha"] = alpha
        data["data"] = m 
        data["sigmas"] = sigmas 
        return (filestate, data) 
    
    def generateChallenge(self, filestate, pk, sk):
        """
        | :math:`$\\text{Q is the set of \\{} (i,\\nu_i)\\text{\\}}$`
        | Where i is a random block index and Nu is a random element.

        Implements :py:func:`POR.PORbase.generateChallenge()`
        """
        print("Generating Challenge...")
        g = RandSubset()
        num_blocks = filestate["num_blocks"]
        kprf = filestate["kprf"]
        alpha = filestate["alpha"]
    
        num_chal = self.num_challenge_blocks
        if (num_blocks < self.num_challenge_blocks):
            num_chal = num_blocks
        print("Challenging", num_chal, "blocks:")
    
        # a set of num_chal block indices
        check_set = g.gen(num_chal, (num_blocks - 1))
        # for each index, generate a random \nu in Z_p
        NU =[int(integer(charm_random(self.prime))) for i in range(len(check_set))]

        Q = {}
        for i in range(len(check_set)):
            Q[check_set[i]] = NU[i] 

        challenge = Q 
        chalData = {}
        chalData["kprf"] = kprf 
        chalData["alpha"] = alpha 
        return(challenge, chalData) 
    
    def generateProof(self, challenge, pk, data):
        """
        | Mu calculation formula:
        | :math:`$\\mu_j \\gets \\sum_{(i,\\nu_i)\\in Q} \\nu_i m_{ij} \\text{ for } 1 \\leqq j \\leqq s$`
        | Final sigma calculation formula:
        | :math:`$\\sigma \\gets \\sum_{(i,\\nu_i)\\in Q} \\nu_i \\sigma_i$`
        Implements :py:func:`POR.PORbase.generateProof()`
        """
        print("Generating Proof...")
        m = data["data"]
        Q = challenge
        sigmas = data["sigmas"]
    
        # compute each \mu, as in the paper
        MU = {}
        for j in range(len(m[0])):
            add = []
            for i in Q:
                add.append(Q[i] * int.from_bytes(m[i][j], byteorder='big'))
            MU[j] = sum(add)
    
        final_sigma =[Q[i] * sigmas[i] for i in Q]
        final_sigma = sum(final_sigma) 
        proof = {}
        proof["MU"] = MU 
        proof["final_sigma"] = final_sigma 
        proof["data"] = m
        return proof 

    def verifyProof(self, proof, challenge, chalData, pk, sk):
        """
        | Final check formula:
        | :math:`$\\sigma \\stackrel{?}{=} \\sum_{(i,\\nu_i)\\in Q} \\nu_i f_{k_{prf}}(i) + \\sum_{j=1}^s \\alpha_j \\mu_j$`
        Implements :py:func:`POR.PORbase.verifyProof()`
        """ 
        print("Verifying Proof...")
        MU = proof["MU"]
        final_sigma = proof["final_sigma"]
        kprf = chalData["kprf"]
        alpha = chalData["alpha"]
        m = proof["data"]
        Q = challenge
    
        if not MU:
            return False
    
        prf = selectPRF(AES,(kprf, MODE_ECB))
        temp1 = [Q[i] * PRF(prf, (i+1), self.prime_len) for i in Q]
        temp2 = [alpha[j] * MU[j] for j in range(len(m[0]))]
        check = sum(temp1) + sum(temp2)
    
        if check == final_sigma:
            return True
        return False
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description ="CPOR-Priv Scheme")
    parser.add_argument("-v", "--verbose", action ="store_true", 
                        default=False, dest="verbose", 
                        help = "Verbose output") 
    parser.add_argument("-f", "--filename", action = "store", 
                        dest = "file_name",
                        help = "Path to file, to store and audit.")
    parser.add_argument("-c", "--challenger", action = "store_true", 
                        default = False,
                        dest = "challenger", 
                        help = "Act as challenger.")
    parser.add_argument("-p", "--prover", action = "store_true", 
                        default = False, dest = "prover", 
                        help = "Act as prover.") 
    parser.add_argument("-l", "--num_audits",
                        action="store", type=int, 
                        default = 3, dest="num_of_audits", 
                        help = "Number of times to audit (default, 3)")
    parser.add_argument("-b", "--block_size",
                        action="store", type = int, 
                        default = 4096, dest="block_size", 
                        help ="Block size in bytes (default, 4096)")
    parser.add_argument("-n", "--num_challenge_blocks",
                        action="store", type=int, default=512,
                        dest="num_chal_blocks", help="Blocks per challenge (default, 512)")
    args = parser.parse_args()
    pdp = CPORpriv(None) 
    pdp.start(args)
