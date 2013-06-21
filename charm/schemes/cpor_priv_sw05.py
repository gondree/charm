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
from charm.toolbox.integergroup import *
from charm.core.crypto.cryptobase.cryptobasemodule import selectPRF
harm/core/crypto/cryptobase/cryptobasemodule.c 
import sys, math, argparse, random


class CPORpriv(PORbase):
    def __init__(self, common_input=None):
		self.enc_key_len = 1024
		self.mac_key_len = 1024
		self.block_size = 4096
		self.sector_size = 9.875
        PORbase.__init__(self, common_input)    

    def set_attributes(self, args):
        """ 
        Implements :py:func:`POR.PORbase.set_attributes()`
        """
		if hasattr(args, 'mac_length'):
            self.mac_key_len = args.mac_length
		if hasattr(args, 'enc_length'):
            self.enc_key_len = args.enc_length
		sectors = self.block_size / self.sector_size
		IntegerGroup.paramgen(self, 80, r=2)

        return None

    def keyGen(self):
        """ 
		|||
		Chooses a random symmetric encryption key, and a random MAC key, and combines them
		to create the secret key. No public key.
		|||

        Implements :py:func:`POR.PORbase.keyGen()`
        """
		pk, sk = dict(), dict()
		k = randomBits(self.mac_key_len)
        sk ["kmac"] = bytes(int2bytes(k))
		k = randomBits(self.enc_key_len)
		sk["kenc"] = bytes(int2bytes(k))
		return (pk, sk)
    
    def tag(self, filename, pk, sk):
        """ 
		|||
		Erasure Codes the file, breaks the file into n blocks, each s sectors long.
		Then a PRF key is chosen along with s random numbers, where s in prime.
		t0 is n concatinated with the  encryption, using the random enc key, of the random s numbers after the PRF key is applied to them. 
		The tag is t0 concated with the MAC, using the MAC key, of (t0).
		For each i, or each block, a sigman is calculated using the PRF key on i which is concated with  all the random number of the sector, times the message sector&block
		formula: sigma[i]=Fk(i) + for j = 1, j <=s, j++: alpha[j]*message[i][j], where k = PRF key, F= some function, s = the total amount of random numbers, i = block id, j = sector id
		M* = {mij}, 1<= i <= n, 1 <= j <= s processed with {sigman[i]}
		|||
        Implements :py:func:`POR.PORbase.tag()`
        """

		# things we need to define during set_attributes or __init__
		sectors =  self.block_size / self.sector_size# the number of sectors in a block
		
		# Opening the file and storing the message.
		File = open(filename, "rb")
		message = File.read()
		File.close()
		
		# things we compute here
		Mprime = ECC(message) # holds the erasure-coded file
		
		if(Mprime%self.block_size != 0):
			num_blocks = Mprime / self.block_size + 1
		else:
			num_blocks = Mprime / block_size  # we can compute this based on Mprime's size and blocksize
								    		  # may need to think of padding fraction of blocks -- the ceil(size of Mprime/blocksize)

		m = [[] for i in range(n)]  # where n is number of blocks in Mprime

		# 
		# code for m splitting the file into blocks and sectors
		# m[i] will hold a list of sectors that comprise block i
		# m[i][j] will hold sector j of block i
		#
		pos = 0
		counter = 0
		while counter < num_blocks:
			if(pos+sectors) < len(Mprime):
				m[counter] = [range(pos, pos+sectors)]
				pos = pos+sectors+1
				counter = counter + 1
			else:
				m[counter] = [range(pos, len(Mprime)]
				while m[counter] < self.block_size:
					m[counter] = m[counter] + "0"
				counter = counter + 1

		#
		# pick some secrets
		#
		k = randomBits(self.enc_key_len)
		kprf = bytes(int2bytes(k))     # a random PRF key
		g = IntegerGroup()
		alpha = g.randomGen(self) for i in range(sectors)  # a list of random numbers from Zp, |alpha| = sectors

		#
		# make the tags
		# Simple tag at this point, need to add in the MAC, encryption, concatination, and turn them to bits
		#
		tag = [num_blocks, kprf, alpha]

		#
		# generate the sigmas
		#
		sigmas=[] # for each block, a sigma is generated with a function using PRFkey on each block, adding the product of all the alphas, and the sectors
		for i in range(num_blocks):
			am = [alpha[j]*m[i][j] for j in range(len(m[i])))]
			prf = cryptobase.selectPRF(AES, (kprf, MODE_ECB), i)
			s = prf + sum(am)
			sigmas.append(s)
		
		data["data"] = m
		data["tag"] = tag
		data["sigmas"] = sigmas
		filestate["tag"] = tag # stored twice to avoid having to retrieve it multiple times
        return (filestate, data)

    def generateChallenge(self, filestate, pk, sk):  
        """
		|||
		Take the sk and use the kmac to verify the MAC on the tag. If invalid abort.
		If not aborted, use kenc on the tag to decrypt the ecnrypted PRF key and the random numbers. 
		Pick a random element, from 1 to num_blocks, and for each(i) add a random element nu, creating the set Q{(i,nui)}
		send Q to the prover.
		||| 
        Implements :py:func:`POR.PORbase.generateChallenge()`
        """
		
		
		#
		# Need to unpack num_blocks, and the encrypted kprf, and alphas to check MAC in packed tag
		#
		
		g = RandSubset()
		num_blocks = filestate["tag"][0]
		kprf = filestate["tag"][1]
		alpha = filestate["tag"][2]
		rand = random(max = num_blocks)
		count = 0
		check_set =  g.gen(random.randint(1, num_blocks), (num_blocks - 1)) # picks a random amount of blocks to check, making sure the amount of blocks
   																		    # picked are within the num_block range
		NU = g.gen(len(check_set, Prime) # same size as check_set, values are generated as random elements from B which is in Zp
		Q = dict() # set of group of check_set and their corresponding NU values
		for x in check_set:
			Q[check_set[x]] = NU[x]
		challenge = Q
		chalData["kprf"] = kprf
		chalData["alpha"] = alpha
        return (challenge, chalData) 
    
    def generateProof(self, challenge, pk, data):  
        """
		|||
		Take the processed file m[][], along with sigma and Q.
		Compute the mu values and sigma value.
		mu for each sector is obtained by multiplying each nui to the same sector in each block.
		the signma value is obtained by the multiplication of the nui and sigma[i] added together with the other blocks value.
		these values are sent back to the verifier
		|||  
        Implements :py:func:`POR.PORbase.generateProof()`
        """
		MU = dict()
		for j in range(len(m[i])):
			add = [NU[i]*m[i][j] for in in range(Q)]
			MU[j] = sum(add)
		final_sigma = [NU[i]*sigma[i] for i in range(Q)]
		final_sigma = sum(final_sigma)
		
		p["MU"] = MU
		p["final_sigma"] = final_sigma
        return p
    
    def verifyProof(self, proof, challenge, chalData, pk, sk):
        """
		|||
		Parse the results obtained from the proover to obtain the mus and sigma
		if parsing fails, then abort
		If no abort then check if the sigma value is correct
		This is done by: concatinating the sum of (the nus for each block multiplied by the PRF of the block) and (the sum of the mus for each sector multiplied by the random number for the sector)
		If these values match the sigma returned from the proover then all is good, otherwise abort.
		|||
        Implements :py:func:`POR.PORbase.verifyProof()`
        """

		if MU == null
			abort
		else
			prf = cryptobase.selectPRF(AES, (chalData["kprf"], MODE_ECB), i) for i in range (Q)
			temp1 = NU[i]*prf[i] for i in range(prf)
			temp2 = alpha[j]*MU[j] for j in range(len(m[i]))
			check = temp1 + temp2
			if check == final_sigma
				good
			else
				abort
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
