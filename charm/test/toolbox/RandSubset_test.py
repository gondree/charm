"""
Unit Test for random subset sampling

:Authors: Krisztina Riebel-Charity and Mark Gondree
:Date:    05/31/2013
"""
import unittest 
from charm.core.math.integer import integer,random
from charm.toolbox.RandSubset import RandSubset

class RandSubsetTest(unittest.TestCase):
    
    def testFullRangeInt(self):
        g = RandSubset()
        for n in range(20):
            print ("Gen %d numbers in [0,%d]" %(n+1, n))
            c = g.gen(n+1, n)
            c.sort(key=int)
            ans = list(range(n+1))
            if c:
                assert c == ans , 'expected a range of numbers'
   
    def testGenWithinRange(self):
        g = RandSubset()
        for r in range(10):
            for n in range(r):
                print ("Gen %d numbers in [0, %d]" %(n, r))
                c = g.gen(n, r)
                for i in c: 
                    assert i <= r, ' not in range'
                assert len(c) == len(set(c)),' not unique'

    def testGenOutOfRange(self):
        g = RandSubset()
        for n in range(10):
            for r in range(n):
                print ("Gen %d numbers [0 to %d]" %(n, r))
                c = g.gen(n, r)
                print(c)
                if c:
                    for i in c: 
                        assert i <= r, ' not in range'
                    assert len(c) == len(set(c)),' not unique'


if __name__ == "__main__":
    unittest.main()

