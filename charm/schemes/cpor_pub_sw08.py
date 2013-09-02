#!/usr/bin/python3
"""
CPOR with Public Verificability

| From paper: Compact Proofs of Retrievavility
| Published in: ASIACRYPT 2008
| By: Hovav Shacham and Brent Waters

:Authors: Mark Gondree and Michael O'Neil
:Date: 07/24/2013
"""
from charm.core.math.pairing import order
from charm.core.engine.protocol import *
from charm.toolbox.RandSubset import RandSubset
from charm.toolbox.POR import PORbase
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import argparse

def int2bytes(v):
    v, r = divmod(v, 256)
    yield r
    if v == 0:
        raise StopIteration
    for r in int2bytes(v):
        yield r

class CPORpub (PORbase):
    def __init__(self, common_input = None):
        PORbase.__init__(self, common_input)
        self.block_size = 4096
        self.group = PairingGroup('MNT224')
        self.prime = int(order(self.group.random(ZR)))
        self.lambda_size = self.prime.bit_length()
        # num chal blocks is \ell, "a conservative choice for \ell is \lambda"
        self.num_challenge_blocks = self.lambda_size
        self.sector_size = (self.lambda_size - 1) / 8  # sectors live in Z_p
        self.group = PairingGroup('MNT224')

    def set_attributes(self, args):
        """ 
        Implements :py:func:`POR.PORbase.set_attributes()`
        """ 
        if hasattr(args, 'block_size'):
            self.block_size = args.block_size
        if hasattr(args, 'num_chal_blocks'):
            self.num_challenge_blocks = args.num_chal_blocks
        return None

    def keyGen(self):
        """ | Chooses random signing keys, and an alpha and vee value.
        | We actually never use the signing keys, because they are only for stateless clients.
        | We hold state, to simplify the challenger side of the protocol.
        | :math:`$\\alpha \\stackrel{R}{\\gets} \\mathbb{Z}_p$`
        |
        | :math:`$v \\gets g^\\alpha$`
        | Implements :py:func:`POR.PORbase.keyGen()`
        """ 
        print("Generating Keys...")
        pk, sk = dict(), dict()
        # sigkey = [Some function returning a signing pub key and a signing priv key]

        generator = self.group.random(G2)
        alpha = self.group.random(ZR) 
        vee = generator ** alpha

        # sk["key"] = sigkey[priv]
        sk["alpha"] = alpha
        # pk["key"] = sigkey[pub]
        pk["vee"] = vee
        pk["g"] = generator
        return (pk, sk) 
    
    def tag (self, filename, pk, sk):
        """ 
        | :math:`$u_1\\text{...,}u_s \\stackrel{R}{\\gets} G$` 
        | Sigma calculation formula:
        | :math:`$\\sigma_i \\gets (H(name||i) * \\prod_{j=1}^s u_j^{m_{ij}})^{\\alpha}$`
        | Implements :py:func:`POR.PORbase.tag()`
        """

        alpha = sk["alpha"]

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
                for j in range(num_sectors):
                    jstart = j * self.sector_size
                    jend = jstart + min(self.sector_size - 1, len (sectors) - jstart)
                    m[i].append(bytes(sectors[int(jstart):int(jend)]))
                block = f.read(self.block_size)
                i = i + 1
        
        # name picked from a large domain like ZR
        name = self.group.hash(filename, ZR)
        
        # Size of U is num_sectors
        u = [self.group.random(G1) for i in range(num_sectors)]

        # generate the sigmas
        sigmas =[]
        for i in range(num_blocks):
            temp = 1
            for j in range(num_sectors):
                temp = temp * (u[j] ** int.from_bytes(m[i][j], 'big'))
            ctxt = name + i
            # Hashes the ctxt as a G1 group memeber
            sigmas.append((self.group.hash(str(ctxt), G1) * temp) ** alpha)

        filestate, data = {}, {}
        filestate["num_blocks"] = num_blocks
        filestate["u"] = u
        filestate["name"] = name
        data["data"] = m
        data["sigmas"] = sigmas
        return (filestate, data)
    
    def generateChallenge(self, filestate, pk, sk):
        """
        | :math:`$\\text{Q is the set of \\{} (i,\\nu_i)\\text{\\}}$`
        | Where i is a random block index and Nu is a random element.
        | Implements :py:func:`POR.PORbase.generateChallenge()`
        """
        print("Generating Challenge...")
        g = RandSubset()
        vee = pk["vee"]
        num_blocks = filestate["num_blocks"]
        name = filestate["name"]
        u = filestate["u"]

        num_chal = self.num_challenge_blocks
        if (num_blocks < self.num_challenge_blocks):
            num_chal = num_blocks
        print("Challenging", num_chal, "blocks:")
    
        # a set of num_chal block indices
        check_set = g.gen(num_chal, (num_blocks - 1))

        # for each index, generate a random \nu in Z_p
        NU =[self.group.random(ZR) for i in range(len(check_set))] 

        Q = {}
        for i in range(len(check_set)):
            Q[check_set[i]] = NU[i]
        
        challenge = Q
        chalData = {}
        chalData["name"] = name
        chalData["u"] = u
        return(challenge, chalData) 
    
    def generateProof(self, challenge, pk, data):
        """
        | Mu calculation formula:
        | :math:`$\\mu_j \\gets \\sum_{(i,\\nu_i)\\in Q} \\nu_i m_{ij} \\in \\mathbb{Z}_p \\text{ for } 1 \\leqq j \\leqq s$`
        | Final sigma calculation formula:
        | :math:`$\\sigma \\gets \\prod_{(i,\\nu_i)\\in Q} \\sigma_{i}^{\\nu_i} \\in G$`
        | Implements :py:func:`POR.PORbase.generateProof()`
        """
        print("Generating Proof...")
        m = data["data"]
        Q = challenge
        sigmas = data["sigmas"]
    
        # compute each \mu, as in the paper
        MU = {}
        for j in range(len(m[0])):
            add = []
            for i in Q.keys():
                # needs to stay within ZR
                elem = int.from_bytes(m[i][j], 'big')
                # casts the existing m[i][j] int value as a ZR group member
                elem = self.group.init(ZR, elem)
                add.append(elem * Q[i])
            MU[j] = sum(add)
    
        holder = [sigmas[i] ** Q[i] for i in Q.keys()]
        final_sigma = 1
        # needs to stay within G
        for i in range(len(holder)):
             final_sigma = final_sigma * holder[i]
        
        proof = {}
        proof["MU"] = MU 
        proof["final_sigma"] = final_sigma 
        proof["data"] = m
        return proof 

    def verifyProof(self, proof, challenge, chalData, pk, sk):
        """
        | Final check calculation formula:
        | :math:`$e(\\sigma, g) \\stackrel{?}{=} e(\\prod_{(i,\\nu_i)\\in Q} H(name||i)^{\\nu_i} * \\prod_{j=1}^s u_j^{\\mu_j}, v)$`
        | Implements :py:func:`POR.PORbase.verifyProof()`
        """ 
        print("Verifying Proof...")
        MU = proof["MU"]
        final_sigma = proof["final_sigma"]
        name = chalData["name"]
        u = chalData["u"]
        m = proof["data"]
        Q = challenge
        vee = pk["vee"]
        g = pk["g"]
    
        if not MU:
            return False
    
        prod1 = 1
        for i in Q:
            ctxt = name + i
            # Hashes as a member of G1
            temp = self.group.hash(str(ctxt), G1)
            temp = temp ** Q[i]
            prod1 = prod1 * temp
        
        prod2 = 1
        for j in range(len(m[0])):
            temp = u[j] ** MU[j]
            prod2 = prod2 * temp

        total = prod1 * prod2

        # To work with the PairingGroup, the values need to be of
        # an asymetrical bilinear map.
        if pair(final_sigma, g) == pair(total, vee):
            return True
        return False
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description ="CPOR-Pub Scheme")
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
    pdp = CPORpub(None) 
    pdp.start(args)
