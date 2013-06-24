#!/usr/bin/python3
"""
CPOR with Private Verificability

| From paper: Compact Proofs of Retrievavility
| Published in: ASIACRYPT 2005

:Authors: 
:Date:    
""" 
from charm.toolbox.pairinggroup import PairingGroup, GT 
from charm.core.math.pairing import hashPair as sha1 
from charm.core.math.integer import integer, random, randomBits 
from charm.core.engine.protocol import * 
from charm.toolbox.symcrypto import MessageAuthenticator 
from charm.toolbox.RandSubset import RandSubset 
from charm.toolbox.POR import PORbase 
from charm.toolbox.integergroup import *
from charm.core.crypto.cryptobase import selectPRF, AES, MODE_ECB
import sys, math, argparse 

def int2bytes(v):
    v, r = divmod(v, 256)
    yield r
    if v == 0:
        raise StopIteration
    for r in int2bytes(v):
        yield r


class CPORpriv (PORbase):
  def __init__(self, common_input = None):
    self.enc_key_len = 1024
    self.mac_key_len = 1024
    self.prf_key_len = 256
    self.block_size = 4096
    self.lambda_size = 80
    self.sector_size = (self.lambda_size - 1) / 8
    self.g = IntegerGroup()
    PORbase.__init__(self, common_input)

  def set_attributes(self, args):
    """ 
        Implements :py:func:`POR.PORbase.set_attributes()`
        """ 
    if hasattr (args, 'mac_length'):
      self.mac_key_len = args.mac_length 
    if hasattr (args, 'enc_length'):
      self.enc_key_len = args.enc_length 
    return None 

  def keyGen(self):
    """ 
    Chooses a random symmetric encryption key, and a random MAC key, and combines them
    to create the secret key. No public key.

        Implements :py:func:`POR.PORbase.keyGen()`
        """ 
    self.g.paramgen(self.lambda_size) 
    pk, sk = dict(), dict()
    k = randomBits(self.mac_key_len) 
    sk["kmac"] = bytes(int2bytes (k)) 
    k = randomBits(self.enc_key_len) 
    sk["kenc"] = bytes(int2bytes(k)) 
    print("Finishes KeyGen")
    return (pk, sk) 

  def tag (self, filename, pk, sk):
    """ 
    Erasure Codes the file, breaks the file into n blocks, each s sectors long.
    Then a PRF key is chosen along with s random numbers, where s in prime.
    t0 is n concatinated with the  encryption, using the random enc key, of the random s numbers after the PRF key is applied to them. 
    The tag is t0 concated with the MAC, using the MAC key, of (t0).
    For each i, or each block, a sigman is calculated using the PRF key on i which is concated with  all the random number of the sector, times the message sector&block
    formula: sigma[i]=Fk(i) + for j = 1, j <=s, j++: alpha[j]*message[i][j], where k = PRF key, F= some function, s = the total amount of random numbers, i = block id, j = sector id
    M* = {mij}, 1<= i <= n, 1 <= j <= s processed with {sigman[i]}
    
    Implements :py:func:`POR.PORbase.tag()`
    """
    print("Calculating Num_sectors")

    # the number of sectors in a block
    num_sectors = int(self.block_size // self.sector_size)
    if (self.block_size % self.sector_size is not 0):
      num_sectors += 1

    print("Opening File")

    f = open(filename, 'rb')
    message = f.read()
    f.close()

    print("Closed file, calculating MPRIME")
    
    #TODO: this is where we would transform via erasure-code in future
    Mprime = len(message) 

    print("CALCULATING NUM_BLOCKS")
    print(Mprime)
    print(self.block_size)

    num_blocks = Mprime // self.block_size
    if (Mprime % self.block_size is not 0):
      num_blocks += 1 

    print("CREATION OF M[I][J]")
    print(int(num_blocks))
    m = [[] for i in range(int(num_blocks))]

    print("OPENING FILE TO BE READ IN AS BLOCKS")

    # Opening the file and storing the message.
    with open(filename, "rb") as f:
      block = f.read(self.block_size)
      i = 0
      while block:
        # parse out the sectors
        sectors = bytearray(block) 
        for j in range(int(num_sectors)):
          jstart = j * self.sector_size 
          jend = jstart + min(self.sector_size - 1, len (sectors) - jstart) 
          m[i].append(sectors[int(jstart):int(jend)])
        block = f.read(self.block_size)
        i = i + 1
    
    print("FILE READ IN AS BLOCKS")
    
    #
    # make the tags:
    # For a stateless verifier, we can store E(kenc; <kprf, alpha>) and MAC(kmac; <num_blocks, ctx>)
    # and store these with the prover;
    # For simplicity, we skip this and store these privately in local state
    # to ensure Prover-Verifier interaction is a Sigma protocol
    #
    kbits = randomBits(self.prf_key_len) 
    kprf = bytes(int2bytes(kbits)) # a random PRF key
    PRF = selectPRF(AES, (kprf, MODE_ECB))

    alpha = [self.g.random()]#for i in range(num_sectors)] # a list of random numbers from Zp, |alpha| = num_sectors
    for i in range(len(alpha)):
        print(alpha[i])

    filestate = {}
    filestate["num_blocks"] = num_blocks
    filestate["kprf"] = kprf 
    filestate["alpha"] = alpha
    #
    # generate the sigmas
    #
    sigmas =[] # for each block, a sigma is generated with a function using PRFkey on each block, adding the product of all the alphas, and the sectors
    for i in range (num_blocks):
      print(alpha[0])
      am = [alpha[j] * int(struct.unpack('>q', m[i][j])[0]) for j in range (len(m[i]))]
      s = PRF(i) + sum(am) 
      sigmas.append(s) 
    
    data = {}
    data["data"] = m 
    data["sigmas"] = sigmas 
    return (filestate, data) 

  def generateChallenge(self, filestate, pk, sk):
    """
    Take the sk and use the kmac to verify the MAC on the tag. If invalid abort.
    If not aborted, use kenc on the tag to decrypt the ecnrypted PRF key and the random numbers. 
    Pick a random element, from 1 to num_blocks, and for each(i) add a random element nu, creating the set Q{(i,nui)}
    send Q to the prover.
    Implements :py:func:`POR.PORbase.generateChallenge()`
    """
    #
    # Need to unpack num_blocks, and the encrypted kprf, and alphas to check MAC in packed tag
    #
    g = RandSubset()
    num_blocks = filestate["tag"][0]
    kprf = filestate["tag"][1]
    alpha = filestate["tag"][2]
    count = 0
    check_set = g.gen(random.randint (1, num_blocks), (num_blocks - 1))
    # picks a random amount of blocks to check, making sure the amount of blocks
    # picked are within the num_block range
    NU =[]
    for i in check_set:
      NU = self.g.random(self) # same size as check_set, values are generated as random elements from B which is in Zp

    Q = dict() # set of group of check_set and their corresponding NU values

    for x in check_set:
      x = x - 1 
      Q[check_set[x]] = NU[x] 

    challenge = Q 
    chalData["kprf"] = kprf 
    chalData["alpha"] = alpha 
    return(challenge, chalData) 

  def generateProof(self, challenge, pk, data):
    """
    Take the processed file m[][], along with sigma and Q.
    Compute the mu values and sigma value.
    mu for each sector is obtained by multiplying each nui to the same sector in each block.
    the signma value is obtained by the multiplication of the nui and sigma[i] added together with the other blocks value.
    these values are sent back to the verifier  
    Implements :py:func:`POR.PORbase.generateProof()`
    """

    MU = {}
    for j in range(len(m[i])):
      add =[NU[i] * m[i][j] for i in range(Q)]
      MU[j] = sum(add)

    final_sigma =[NU[i] * sigma[i] for i in range(Q)]
    final_sigma = sum(final_sigma) 
    p = {}
    p["MU"] = MU 
    p["final_sigma"] = final_sigma 
    return p 

  def verifyProof(self, proof, challenge, chalData, pk, sk):
    """
    Parse the results obtained from the proover to obtain the mus and sigma
    if parsing fails, then abort
    If no abort then check if the sigma value is correct
    This is done by: concatinating the sum of (the nus for each block multiplied by the PRF of the block) and (the sum of the mus for each sector multiplied by the random number for the sector)
    If these values match the sigma returned from the proover then all is good, otherwise abort.
    Implements :py:func:`POR.PORbase.verifyProof()`
    """ 
    if MU == null:
      return False
    else:
      prf = cryptobase.selectPRF(AES, (chalData["kprf"], MODE_ECB)) 
      temp1 = [NU[i] * prf(i) for i in range(Q)]
      temp2 = [chalData["alpha"][j] * proof["MU"][j] for j in range(len(m[i]))]
      check = sum(temp1) + sum(temp2) 

      if check == proof["final_sigma"]:
        return True
      else:
        return False 


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description ="CPOR-Priv Scheme")
  parser.add_argument("-v", "--verbose", action ="store_true", 
            default=False, dest="verbose", 
            help = "Verbose output") 
  parser.add_argument("-f", "--filename", action = "store", 
            dest = "file_name",
            help = "Path to file, to store and audit.")
  parser.add_argument ("-c", "--challenger", action = "store_true", 
            default = False,
            dest = "challenger", 
            help = "Act as challenger.")
  parser.add_argument ("-p", "--prover", action = "store_true", 
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
  args = parser.parse_args()
  pdp = CPORpriv(None) 
  pdp.start(args)
