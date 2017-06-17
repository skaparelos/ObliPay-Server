from petlib.ec import Bn
from hashlib import sha256
import msgpack
import utils
import base64

#from petlib.cipher import Cipher
#from os import urandom
def encryptFile(filename):
    #TODO
    pass

def decryptFile(filename):
    #TODO
    pass

def marshall(to_pack):
    packed = msgpack.packb(to_pack, default=utils.default, use_bin_type=True)
    packed_encoded = base64.b64encode(packed)
    return packed_encoded

def unmarshall(packed_encoded):
    packed = base64.b64decode(packed_encoded)
    data   = msgpack.unpackb(packed, ext_hook=utils.ext_hook, encoding='utf-8')
    return data

# function taken from
# https://github.com/gdanezis/petlib/blob/master/examples/GK15ringsig.py
def _challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = list(map(str, elem))
    elem_len = list(map(lambda x: "%s||%s" % (len(x) , x), elem_str))
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return Bn.from_binary(H.digest())


def _verifyCommitment(params, C, proof):
    """ Verify a proof of knowledge of the commitment.
        Return a boolean denoting whether the verification succeeded. """
    (_,_,_,_,_,hs) = params
    c, (r0, r1) = proof
    W = r0 * hs[0] + r1 * hs[1] + c * C 
    return _challenge([hs[0], hs[1], C, W]) == c

 
def _verifyPositivity(params, listP):
     ''' Verifies that a 32 bit number is positive or 0. '''
     #TODO : assert len(listP) == 32

     (com, commitmentsList, proof_list) = listP

     Product_Com = commitmentsList[0]
     assert _VerifyZeroOne(params, commitmentsList[0], proof_list[0]) == True

     for i,c in enumerate(commitmentsList[1:]):
         #Verify that it is 0 or 1
         assert _VerifyZeroOne(params, c, proof_list[i+1]) == True
         # Product(Com(xi,ri)^2i)
         Product_Com = Product_Com + (2**(i+1)) * c

     # E(x,r)  == Product( E(xi,ri) )
     return com == Product_Com 


# function taken from
# https://github.com/gdanezis/petlib/blob/master/examples/GK15ringsig.py
def Com(h0, r, h1, m):
    """ Pedersen Commitment. """
    return r * h0 + m * h1


#Function taken from
# https://github.com/gdanezis/petlib/blob/master/examples/GK15ringsig.py
def _VerifyZeroOne(params, c, proof):
    """ Verify that a Commitment c = Com(m,r) is either 0 or 1 """
    (_, o, _, _, _, hs) = params 
    (x, f, za, zb) = proof

    assert 0 < x < o
    assert 0 < f < o
    assert 0 < za < o
    assert 0 < zb < o

    ca = Com(hs[0], za, hs[1], f) - x * c
    cb = Com(hs[0], zb, hs[1], 0) - (x-f) * c
    xp = _challenge([hs[0], hs[1], ca, cb]) % o
    return xp == x


def verifySplitCoin(params, publicParams):
    """ Verifies that the attributes of the 2 new commitments add up 
    to the previous """
    (h0gamma, h1gamma, ggamma, zeta1, Cp, Cpp, proof) = publicParams
    (_, o, g, _, _, hs) = params 
    h0 = hs[0]
    h1 = hs[1]

    c , responses = proof
    (r_R, r_gamma, r_Rp, r_split1, r_Rpp, r_split2, r_rnd) = responses

    W1 = r_R * h0gamma + r_split1 * h1gamma + r_split2 * h1gamma \
        + r_rnd * ggamma + c * zeta1
    W2 = r_Rp * h0 + r_split1 * h1 + c * Cp
    W3 = r_Rpp * h0 + r_split2 * h1 + c * Cpp

    #TODO verify positivity (see proof at dissertation document)

    return _challenge([h0, h1, g, h0gamma, h1gamma, ggamma, zeta1, 
            Cp, Cpp, W1, W2, W3]) == c


def verifySpend(params, publicParams, proof):
    (h0gamma, h1gamma, ggamma, zeta1) = publicParams
    (_, o, g, _, z, hs) = params
    (c , responses) = proof
    (r_R, r_gamma, r_L1, r_rnd) = responses
    W1 = r_R * h0gamma + r_L1 * h1gamma + r_rnd * ggamma + c * zeta1
    return _challenge([hs[0], hs[1], g, z, h0gamma, h1gamma, ggamma, zeta1, W1]) == c


def verifyCombineCoin(params, public, proof):
    (_, o, g, _, _, hs) = params 
    c , responses = proof
    (r_R, r_gamma, r_x, r_rnd, r_Rp, r_gammap, r_y, r_rndp, r_Rpp) = responses

    W1 = r_R * public["h0gamma_c1"] + r_x * public["h1gamma_c1"] + \
                    r_rnd * public["ggamma_c1"] + c * public["zeta1_c1"]

    W2 = r_Rp * public["h0gamma_c2"] + r_y * public["h1gamma_c2"] + \
                    r_rndp * public["ggamma_c2"] + c * public["zeta1_c2"]

    W3 = r_Rpp * hs[0] + r_x * hs[1] + r_y * hs[1] + \
                    c * public["C"]

    #TODO verify positivity (see proof at dissertation document)

    return c == _challenge([hs[0], hs[1], public["h0gamma_c1"], 
                    public["h1gamma_c1"], public["ggamma_c1"], 
                    public["h0gamma_c2"], public["h1gamma_c2"], 
                    public["ggamma_c2"], public["zeta1_c1"], 
                    public["zeta1_c2"], public["C"], W1, W2, W3])


def verifyCommitmentAndPositivity(params, C, proofs):
    proofCom, comList, proofList = proofs
    return _verifyCommitment(params, C, proofCom) == True and \
           _verifyPositivity(params, (C, comList, proofList)) == True
