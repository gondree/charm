from toolbox.sigmaprotocol import *
from toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair

class SigmaProtocol1(Sigma):
    def __init__(self, groupObj, common_input=None):
        Sigma.__init__(self, groupObj, common_input)
    
    def prover_state1(self):
        (g, h, H) = Sigma.get(self, ['g', 'h', 'H'])
        r = self.group.random(G2)
        a = pair(g, r)
#        Sigma.store(self, ('r', r), ('a',a), ('g', g), ('h', h), ('H',H) )
        Sigma.setState(self, 3)
        return { 'r':r, 'a':a, 'g':g, 'h':h, 'H':H }        
    
    def prover_state3(self, input):
        (r, h, c) = Sigma.get(self, ['r','h','c'])
#        c = input['c']
        z = r * (h ** -c)
        Sigma.store(self, ('z', z) )
        Sigma.setState(self, 5)
        return {'z':z }

    def prover_state5(self, input):
        Sigma.setState(self, None)
        Sigma.setErrorCode(self, input)
        return None

    def verifier_state2(self, input):
#        Sigma.store(self, ('g',input['g']), ('h',input['h']), ('H',input['H']) ) 
        c = self.group.random(ZR)
#        Sigma.store(self, ('r', input['r']), ('a', input['a']), ('c', c) )
        Sigma.store(self, ('c', c) )
        Sigma.setState(self, 4)
        return {'c':c }
        
    def verifier_state4(self, input):
#        z = input['z']
        (g, H, a, c, z) = Sigma.get(self, ['g','H','a', 'c','z'])
        if a == (pair(g,z) * (H ** c)):
            print("SUCCESS!!!!!!!"); result = 'OK'
        else:
            print("Failed!!!"); result = 'FAIL'
        Sigma.setState(self, 6)
        Sigma.setErrorCode(self, result)
        return result

    def verifier_state6(self, input):
        Sigma.setState(self, None)
        return None

