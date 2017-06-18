import acl
import crypto
import database


def ACLSpend(params, encoded):
    (h0gamma, h1gamma, ggamma, zeta1, proof, coin) = crypto.unmarshall(encoded)
    publicParams = (h0gamma, h1gamma, ggamma, zeta1)
    if crypto.verifySpend(params, publicParams, proof) == False:
        return "Couldn't verify coin spend"
    return "coin spend verified!"


def ACLSplit(params, sessionid, encoded, db, keys):
    """
	When a user wants to split two coins, he must call this function.
	It takes as input: h0^gamma, h1^gamma, g^gamma, zeta1, Cp, Cpp, proof, coin
	-zeta1 is the blinded coin the user has obtained from the service in the past
	-Cp, Cpp are the 2 commitments that will be used to register.
    	-proof is a NIZK which proves that what is hidden in the commitments adds up 
	 to the values within zeta1
	-coin is the coin the user will split. This coin must be verified
	"""
    (h0gamma, h1gamma, ggamma, zeta1, Cp, Cpp,
     proof, proofp, proofpp, coin) = crypto.unmarshall(encoded)

    (issuer_pub, numAttr, signature, sig) = coin

    # verify positivity
    if crypto.verifyCommitmentAndPositivity(params, Cp, proofp) == False:
        return "Couldn't verify the Cp commitment"

    if crypto.verifyCommitmentAndPositivity(params, Cpp, proofpp) == False:
        return "Couldn't verify the Cpp commitment"

    # Verify the split coin proof
    verifyParams = (h0gamma, h1gamma, ggamma, zeta1, Cp, Cpp, proof)
    if crypto.verifySplitCoin(params, verifyParams) == False:
        return "Couldn't verify proof of SplitCoin"

    # Verify that there is no double spending and invalidate the coin
    # so it can't be further used
    toPack = [issuer_pub, numAttr, signature, sig]
    encoded_coin = crypto.marshall(toPack)
    if ACLVerify(params, encoded_coin, db, keys, innerCall=True) == False:
        return "ACL verification failed due to double spending."

    # If the code reaches here, the service must create
    # what is needed by the user to create two coins

    # save sessionid
    if _saveSessionid(sessionid, db) == -1:
        return -1
    if _saveSessionid("".join([sessionid, "coin2"]), db) == -1:
        return -1

    issuer_pub = keys[1]  # acl.BL_issuer_keys()

    ### ACL Preparation ###
    # rndp and rndpp are to be sent to the user
    # z1, z2 are private, not to be sent
    rnd_p, z1_p, z2_p = _ACLPreparation(params, sessionid, Cp)
    rnd_pp, z1_pp, z2_pp = _ACLPreparation(params, sessionid, Cpp)
    if rnd_p == -1 or rnd_pp == -1:
        return -1

    ### ACL Validation 1 ###
    (a_p, a1p_p, a2p_p) = _ACLValidation1(params, sessionid, z1_p, z2_p, db)
    sessionid = "".join([sessionid, "coin2"])
    (a_pp, a1p_pp, a2p_pp) = _ACLValidation1(params, sessionid, z1_pp, z2_pp,
                                             db)

    ### Prepare to return ###
    ret_p = [rnd_p, a_p, a1p_p, a2p_p]
    ret_pp = [rnd_pp, a_pp, a1p_pp, a2p_pp]
    ret = [ret_p, ret_pp, issuer_pub]
    retEncoded = crypto.marshall(ret)

    return retEncoded


def ACLCombine(params, sessionid, encoded, db, keys):
    (public, proof) = crypto.unmarshall(encoded)

    # Verify that indeed the new commitment
    # is the sum of the 2 given
    if crypto.verifyCombineCoin(params, public, proof) == False:
        return "Proof of combineACL failed."

    ## check that is not the same coin sent two times
    # Prepare the arguments
    verifyParams1 = [public["issuer_pub_c1"], public["numAttr_c1"],
                     public["signature_c1"], public["sig_c1"]]
    verifyParams2 = [public["issuer_pub_c2"], public["numAttr_c2"],
                     public["signature_c2"], public["sig_c2"]]

    if public["signature_c1"] == public["signature_c2"] or \
                    public["sig_c1"] == public["sig_c2"]:
        return "Are you using the same coin?"

    verifyParams1Encoded = crypto.marshall(verifyParams1)
    verifyParams2Encoded = crypto.marshall(verifyParams2)

    # check double spending
    if ACLVerify(params, verifyParams1Encoded, db, keys,
                 innerCall=True) == False or \
                    ACLVerify(params, verifyParams2Encoded, db, keys,
                              innerCall=True) == False:
        return "ACL verification failed due to double spending."

    # save session
    if _saveSessionid(sessionid, db) == -1:
        return -1

    userCom = public["C"]
    issuer_pub = keys[1]  # acl.BL_issuer_keys()

    ### ACL Preparation ###
    aclPrep = _ACLPreparation(params, sessionid, userCom)
    if aclPrep == -1:
        return -1
    (rnd, z1, z2) = aclPrep

    ### ACL Validation 1 ###
    (a, a1p, a2p) = _ACLValidation1(params, sessionid, z1, z2, db)

    ### Prepare to return ###
    ret = [rnd, a, a1p, a2p, issuer_pub]
    retEncoded = crypto.marshall(ret)
    return retEncoded


def ACLDeposit(params, sessionid, encoded, db, keys):
    (userCom,) = crypto.unmarshall(encoded)

    # since the user has gotten thus far and has began registration
    # add the session id in the database
    if _saveSessionid(sessionid, db) == -1:
        return -1

    issuer_pub = keys[1]  # acl.BL_issuer_keys()

    ### ACL Preparation ###
    aclPrep = _ACLPreparation(params, sessionid, userCom)
    if aclPrep == -1:
        return -1
    (rnd, z1, z2) = aclPrep

    ### ACL Validation 1 ###
    (a, a1p, a2p) = _ACLValidation1(params, sessionid, z1, z2, db)

    ### Prepare to return ###
    ret = [rnd, a, a1p, a2p, issuer_pub]
    retEncoded = crypto.marshall(ret)
    return retEncoded


def _ACLPreparation(params, sessionid, userCom):
    """Executes ACLPreparation and returns rnd """
    msg_to_user = acl.BL_issuer_preparation(params, sessionid, userCom)
    (rnd, z1, z2) = msg_to_user
    return rnd, z1, z2


def _ACLValidation1(params, sessionid, z1, z2, db):
    issuer_state = acl.StateHolder()
    issuer_state.z1 = z1
    issuer_state.z2 = z2
    (a, a1p, a2p) = acl.BL_issuer_validation(params, sessionid, issuer_state,
                                             db)
    return (a, a1p, a2p)


import settings
def ACLValidation2(params, sessionid, encoded, db, keys):
    # 50 for GID=713, 55 for GID=714, 75 for GID=715, 100 for GID=716
    length = 50
    if settings.SERVER_GID == 713:
        length = 50
    elif settings.SERVER_GID == 714:
        length = 55
    elif settings.SERVER_GID == 715:
        length = 75
    elif settings.SERVER_GID == 716:
        length = 100

    # This check basically distinguishes if the sender sends 2 things or one
    # i.e. if we are in a splitACL phase or not
    if len(encoded) < length:
        (msg_to_issuer,) = crypto.unmarshall(encoded)

        issuer_state = database.getIssuerState(sessionid, db)
        msg_to_user = acl.BL_issuer_validation_2(params, issuer_state,
                                                 msg_to_issuer, keys)

        encoded = crypto.marshall([msg_to_user])
        return encoded

    else:  # splitACL
        (msg_to_issuer_p, msg_to_issuer_pp) = crypto.unmarshall(encoded)

        issuer_state_p = database.getIssuerState(sessionid, db)
        msg_to_user_p = acl.BL_issuer_validation_2(params, issuer_state_p,
                                                   msg_to_issuer_p, keys)

        issuer_state_pp = database.getIssuerState(sessionid, db)
        msg_to_user_pp = acl.BL_issuer_validation_2(params, issuer_state_pp,
                                                    msg_to_issuer_pp, keys)

        encoded = crypto.marshall([msg_to_user_p, msg_to_user_pp])
        return encoded


def ACLVerify(params, encoded, db, keys, innerCall=False):
    """ Verifies a coin. Returns False if verification failed,
	    a value otherwise. """

    (issuer_pub, numOfAttributes, signature, sig) = crypto.unmarshall(encoded)

    m = acl.BL_verify_cred(params, issuer_pub, numOfAttributes,
                           signature, sig, db, keys)

    if m == False:
        return False
    else:
        encoded = crypto.marshall([m])
        return encoded


def ACLDoubleSpent(params, encoded):
    #toPack = [issuer_pub, numAttr, signature, sig]
    #encoded_coin = crypto.marshall(toPack)

    #if ACLVerify(params, encoded_coin, db, keys, innerCall=True) == False:
    #    return "ACL verification failed due to double spending."
    #return False
    pass


def _saveSessionid(sessionid, db):
    # save sessionid in the database
    if database.sessionExists(sessionid, db) == False:
        if database.insert2DB_session(sessionid, db) == -1:  # writing failed
            return -1
    else:  # if session already exists
        return -1
