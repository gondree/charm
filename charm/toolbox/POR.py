"""
Proofs of Retrievability / Proofs of Data Possession

A generic class for POR interactive proofs.

:Authors: Krisztina Riebel-Charity and Mark Gondree
:Date:    05/31/2013
"""
from charm.core.engine.protocol import *
from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.enum import Enum
from socket import socket,AF_INET,SOCK_STREAM,SOL_SOCKET,SO_REUSEADDR
import sys, time

party = Enum("Prover", "Challenger")
CHALLENGER,PROVER = party.Challenger, party.Prover
HOST, PORT = "", 8082

class PORbase(Protocol):
    def __init__(self, common_input=None):
        Protocol.__init__(self, None)  
 
        # This is a hack:
        # Protocol class requires a "group" attribute with serialization logic
        self.group = IntegerGroupQ(0)
        
        prover_states = { 2:self.prover_state2, 
            4:self.prover_state4, 6:self.prover_state6, 
            8:self.prover_state8, 10:self.prover_state10  }
        challenger_states = { 1:self.challenger_state1, 
            3:self.challenger_state3, 5:self.challenger_state5, 
            7:self.challenger_state7, 9:self.challenger_state9 }
        prover_trans = { 2:4, 4:6, 6:[4,8,10] }
        challenger_trans = { 1:3, 3:5, 5:[3,7,9] }
        Protocol.addPartyType(self, PROVER, prover_states, prover_trans)
        Protocol.addPartyType(self, CHALLENGER, challenger_states, 
            challenger_trans, True)

    def set_attributes(self, args):
        """ Sets scheme-specific properties for the POR scheme.
        """
        return NotImplemented

    def keyGen(self):
        """ Generates any relevant public key *pk* and priviate key *sk* 
        data for the scheme.
        
        :returns: (pk, sk)
        """
        return NotImplemented
    
    def tag(self, filename, pk, sk):
        """ Generates tag data to be stored with the file.

        :param filename: The path to the file to tag
        :param pk: A public key
        :param sk: A private key
        :returns: (filestate, data)
        """
        return NotImplemented

    def generateChallenge(self, filestate, pk, sk):  
        """ Generates a challenge *c*, that can be sent to a prover.
        For some schemes, some secret *chalData* must be held locally,
        to verify the proof later.

        :param filestate: Data needed by the challenger.
        :param pk: A public key
        :param sk: A private key
        :returns: (challenge, chalData)
        """
        return NotImplemented


    def generateProof(self, challenge, pk, data):  
        """ Generates a proof *p* based on the challenge.

        :param challenge: The challenge
        :param pk: the public key
        :param data: The file data and tag data
        :returns: p
        """
        return NotImplemented
    
    def verifyProof(self, proof, challenge, chalData, pk, sk):
        """ Checks to see if a proof is valid relative to a challenge.

        :param proof: The proof
        :param challenge: The challenge sent to the prover
        :param challengeData: Extra data held to verify the challenge
        :param pk: The public key
        :param sk: The secret key, if needed (if not publically verifiable)
        :returns: True if verification succeeds, else False.
        """
        return NotImplemented


    """ CHALLENGER states  """     
    def challenger_state1(self):
        """ POR initial state for the challenger.
        
        Generates key data, pre-process the local file to create
        the tag data, and send the file / tag data to the remove server.
        
        * Receive: None
        * Send: The file and tag data.
        * Store: Key data and data used during verification.
        """
        Protocol.store(self, ("num_audits",self.args.num_of_audits), 
                             ("filename",self.args.file_name))
        pk, sk = self.keyGen()
        state, data = self.tag(self.args.file_name, pk, sk)
        Protocol.store(self, ("pk",pk), ("sk",sk), 
                             ("data",data), ("filestate",state))
        Protocol.setState(self, 3)
        return {'filename':self.args.file_name, 'pk':pk, 'data':data}

    def challenger_state3(self, input):
        """ POR challenger issues a challenge to the prover. 
                
        * Receive: Acknowledgement that the prover is ready for an audit.
        * Send: A challenge.
        * Store: The challenge, to be used during the verification stage.
        """
        if self.verbose:
            print("3 => Generate challenge state.")
        state, pk, sk = Protocol.get(self, ["filestate", "pk", "sk"])
        chal, cdata = self.generateChallenge(state, pk, sk)
        Protocol.store(self, ("c",chal), ("cdata", cdata))
        Protocol.setState(self, 5)
        return {'c':chal, 'pk':pk}
 
    def challenger_state5(self, input):
        """ POR challenger verifies the proof. 
        
        The challenger checks if the proof if valid. If the verification fails, 
        we go to the Fail state; if success and the max number of audits have 
        been issued, go to the Success state; otherwise, return to this state 
        to issue another challenge.
        
        * Receive: A proof.
        * Send: The result of the audit.
        * Store: The number of successful or failed audits.
        """
        if self.verbose:
            print("5 => Verify challenge state")
        p, c, cd, pk, sk = Protocol.get(self, ["p", "c", "cdata", "pk", "sk"])
        proof = self.verifyProof(p, c, cd, pk, sk)
        num_audits = Protocol.get(self, ["num_audits"])[0]
        if proof and num_audits > 1:
            if self.verbose:
                print("Successful verification.")
            output = "Challenger : ACCEPTED!"
            Protocol.setState(self, 3)
        elif not proof:
            if self.verbose:
                print("Failed verification.")
            output = "Challenger : FAILED!"
            Protocol.setState(self, 7)
        else:
            if self.verbose:
                print("Finished verification.")
            output = "Challenger : FINISHED!"
            Protocol.setState(self, 9)
        num_audits -= 1
        Protocol.store(self, ("num_audits",num_audits))
        return output

    def challenger_state7(self, input):
        """ POR challenger reaches this state after a proof fails an audit.
        
        * Receive: None.
        * Send: None.
        * Store: None.
        """
        if self.verbose:
            print("7 => Challenger Fail state")
        output = "Challenger : FAILED!"
        Protocol.setState(self, None)
        return output

    def challenger_state9(self, input):
        """ POR challenger reaches this state after all audits are passed.
        
        * Receive: None.
        * Send: Status message.
        * Store: None.
        """
        if self.verbose:
            print("9 => Challenger Success state")
        print("The prover successfully completed verification.")
        Protocol.setState(self, None)
        return "Challenger : ACCEPTED!"

    # PROVER states
    def prover_state2(self, input):
        """ POR initial Prover state.
        
        Stores data and sends acknowledgement.
        
        * Receive: Data from the challenger, to be stored.
        * Send: An acknowledgement of success.
        * Store: The file and its tag data.
        """
        if self.verbose:
            print("2 => This is the first prover state.")
        Protocol.setState(self, 4)
        return "Received Data"

    def prover_state4(self, input):
        """ POR prover generates a proof and sends it to the challenger. 
        
        * Input: A challenge.
        * Processing: The prover generates a proof.
        * Send: A proof.
        * Store: None.
        """        
        if self.verbose:
            print("4 => This is the generate proof state.")
        c, pk, data = Protocol.get(self, ["c", "pk", "data"])
        p = self.generateProof(c, pk, data)
        Protocol.store(self, ("p",p))
        Protocol.setState(self, 6)
        return {"p":p}

    def prover_state6(self, input):
        """ POR prover receives the result of the audit from the challenger. 
        If the proof was verified and the maximum number of challenges has not 
        been issued, return to respond to a new challenge; if the proof failed 
        verification, go to the Fail state; otherwise, go to the Success state.
        
        * Input: A status message indicating the result.
        * Send: A status message.
        * Store: None.
        """
        if self.verbose:
            print("6 => Prover received the result of audit.")
        result = input.split(":")[1]        
        if result == " ACCEPTED!":
            if self.verbose:
                print("Successful verification.")
            output = "prover : ACCEPTED!"
            Protocol.setState(self, 4)
        elif result == " FAILED!":
            if self.verbose:
                print("Failed verification.")
            output = "prover : FAILED!"
            Protocol.setState(self, 8)
        else:
            if self.verbose:
                print("Completed verification.")
            output = "prover : FINISHED!"
            Protocol.setState(self, 10)
        return output

    def prover_state8(self, input):
        """ POR prover reaches this state after any proof fails the audit.
        
        * Input: None.
        * Send: None.
        * Store: None.
        """
        print("Failed verification.")
        Protocol.setState(self, None)
        return None

    def prover_state10(self, input):
        """ POR prover reaches this state after all proofs pass the audit.

        * Input: None.
        * Send: None.
        * Store: None.
        """
        print("Finished verification!")
        Protocol.setState(self, None)
        return None

    def start(self, opts):
        if not hasattr(opts, 'num_of_audits'):
            exit(-1)
        if not hasattr(opts, 'prover') and not hasattr(opts, 'challenger'):
            exit(-1)
        self.args = opts
        self.set_attributes(self.args)
        self.verbose = False
        if hasattr(self.args, 'verbose'):
            self.verbose = self.args.verbose

        if self.args.prover:
            print("Prover: operating as server...")
            svr = socket(AF_INET, SOCK_STREAM)
            svr.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            svr.bind((HOST, PORT))
            svr.listen(1)
            svr_sock, addr = svr.accept()
            print("Connected by ", addr)
            _name, _type, _sock = "prover", PROVER, svr_sock
        elif self.args.challenger:
            print("Challenger: operating as a client...")
            clt = socket(AF_INET, SOCK_STREAM)
            clt.connect((HOST, PORT))
            clt.settimeout(None)
            _name, _type, _sock = "challenger", CHALLENGER, clt
        else:
            return None
        self.setup({'name':_name, 'type':_type, 'socket':_sock})
        self.execute(_type)
