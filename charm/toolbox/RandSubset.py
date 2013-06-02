"""
Random Subset Sampling

| From: Jon Bentley, Robert Floyd, "Programming Pearls: a sample of brilliance" 
| Published in: Communications of the ACM, September 1987, Volume 30, Number 9
| Available at: http://dx.doi.org/10.1145/30401.315746

:Authors: Krisztina Riebel-Charity and Mark Gondree
:Date: 05/04/2013
"""
from charm.core.math.integer import integer,random

class RandSubset:
    """ Generate n random numbers in the range [0, r] using Floyd's algorithm.
    """
    def __init__(self):
        return None

    def gen(self, n, r):
        if n > r+1: 
            print("There aren't %d numbers in the range [0, %d]" %(n, r))
            return None

        ans = []
        for j in range (r-n+1, r+1):
            rand = int(integer(random(j+1)))
            if (rand in ans):
                ans.append(j)
            else:
                ans.append(rand)
        return ans
