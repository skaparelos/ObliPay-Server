# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# See: 
#  Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light." 
#  Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security. 
#  ACM, 2013.

from hashlib import sha256
from base64 import b64encode

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from genzkp import *
import crypto

class StateHolder(object):
    pass

def _saveKeys(keys, filename = 'keys.txt'):
    f = open(filename, 'w+')
    f.write(keys)
    f.close()


def BL_issuer_keys(keys):    
    #Generate and save keys
    #x = q.random()
    #y = x * g
    #toPack = [x, y]
    #encoded = crypto.marshall(toPack)
    #_saveKeys(encoded)

    #Load keys
    #_, y = _loadKeys()
    
    return y


def BL_issuer_preparation(params, sessionid, Com):
    (_, q, g, _, z, _) = params 
    #(C, ) = user_commit
    
    # Preparation
    rnd = q.random()
    z1 = Com + rnd * g
    z2 = z + (-z1)

    if rnd % q == 0:
        raise

    return rnd, z1, z2

def BL_issuer_validation(params, sessionid, issuer_state, db):
    (_, q, g, h, _, _) = params 

    u, r1p, r2p, cp = [q.random() for _ in range(4)]
    a = u * g
    a1p = r1p * g + cp * issuer_state.z1
    a2p = r2p * h + cp * issuer_state.z2

    issuer_state.u = u
    issuer_state.r1p = r1p
    issuer_state.r2p = r2p
    issuer_state.cp = cp

    data = (u, r1p, r2p, cp)

    if database.updateDB_validation1(sessionid, data, db) == -1:
        return -1

    return (a, a1p, a2p)    


def BL_issuer_validation_2(params, issuer_state, msg_from_user, keys):
    (_, q, _, _, _, _) = params 
    x = keys[0]
    e = msg_from_user

    ## Send: (e,) to Issuer
    c = e.mod_sub(issuer_state.cp, q)
    r = issuer_state.u.mod_sub((c * x), q)

    msg_to_user = (c, r, issuer_state.cp, issuer_state.r1p, issuer_state.r2p)
    return msg_to_user


import database
def BL_check_signature(params, issuer_pub, signature, db, keys):
    (_, q, g, h, z, _) = params
    (y_issuer,)  = issuer_pub
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    #load this service's public key
    y_verifier = keys[1]

    if y_issuer != y_verifier:
        print "This verifier didn't issue this key"
        return False

    lhs = (om + omp) % q
    rhs_h = [zet, zet1, 
            ro * g + om * y_verifier,
            ro1p * g + omp * zet1,
            ro2p * h + omp * zet2,
            mu * z + omp * zet]
    
    Hstr = list(map(EcPt.export, rhs_h)) + [m]
    Hhex = b"|".join(map(b64encode, Hstr))
    rhs = Bn.from_binary(sha256(Hhex).digest()) % q
    
    #Check the database to see if this hash already exists!
    coinExists = database.checkDB_coinExists(rhs, db) 

    if rhs == lhs and coinExists == False:
        database.insert2DB_Coin(rhs, db)
        return m
    else:
        return False


def BL_cred_proof(params, user_state):
    (G, q, g, h, z, hs) = params 
    gam = user_state.gam

    assert user_state.zet == user_state.gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g

    Cnew = user_state.rnd * gam_g + user_state.R * gam_hs[0]
    for i, attr in enumerate(user_state.attributes):
        Cnew = Cnew + attr * gam_hs[1+i]
    assert Cnew == user_state.zet1


def BL_show_zk_proof(params, num_attrib):
    (G, _, _, _, _, _) = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables

    gam, rnd, R = zk.get(Sec, ["gam", "rnd", "R"])
    attrib = zk.get_array(Sec, "attrib", num_attrib, 0)

    g, z, zet, zet1 = zk.get(ConstGen, ["g", "z", "zet", "zet1"])
    hs = zk.get_array(ConstGen, "hs", num_attrib+1, 0)
    
    zk.add_proof(zet, gam * z)

    gam_g = zk.get(Gen, "gamg")
    zk.add_proof(gam_g, gam * g)

    gam_hs = zk.get_array(Gen, "gamhs", num_attrib+1, 0)

    for gam_hsi, hsi in zip(gam_hs, hs):
        zk.add_proof(gam_hsi, gam * hsi)
    
    Cnew = rnd * gam_g + R * gam_hs[0]
    for i, attr in enumerate(attrib):
        Cnew = Cnew + attr * gam_hs[1+i]

    zk.add_proof(zet1, Cnew)
    return zk


def BL_verify_cred(params, issuer_pub, num_attributes, signature, sig, db, keys):
    (_, _, g, _, z, hs) = params

    m = BL_check_signature(params, issuer_pub, signature, db, keys) 

    if m == False:
        return False   

    (m, zet, zet1, _, _, _, _, _, _, _) = signature

    zk = BL_show_zk_proof(params, num_attributes)

    env = ZKEnv(zk)

    # Constants
    env.g = g
    env.z = z
    env.zet = zet
    env.zet1 = zet1
    env.hs = hs[:num_attributes + 1]

    ## Extract the proof
    res = zk.verify_proof(env.get(), sig)
    assert res

    return m

