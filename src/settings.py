DB_LOCATION = 'ObliviousPayments.db'

# Flask secret key to sign cookies for sessions
# Generate this randomly.
# You may load this from the environment using (please do it)
# FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
FLASK_SECRET_KEY = 'not_a_secret'

# The elliptic curve to use
SERVER_GID = 713

# Server keys contain the public and secret keys
# These correspond to the BL issuer keys
# You may load this from the environment using (please do it)
# SERVER_KEYS = os.environ.get('SERVER_KEYS')
# This is set randomly to make the code work.
# (!!DO NOT USE THIS ONE!!)
SERVER_KEYS = 'kscdACsE83pXJI4zkcCLApX6WaZsiduOQa9Orf3ZvwT9xyICks0Cyb0CHR96/NVeFEq/bZJnvVL0Q7JEsO18Nl234HOajA=='
#SERVER_KEYS for different elliptic curves:
#gid=713:
#SERVER_KEYS = 'kscdACsE83pXJI4zkcCLApX6WaZsiduOQa9Orf3ZvwT9xyICks0Cyb0CHR96/NVeFEq/bZJnvVL0Q7JEsO18Nl234HOajA=='
#gid=714:
#SERVER_KEYS = 'kschACs9jA63UbHE+ajwwSSjQtvJoIi1cN3i4e9RLcbxEGx5l8coApLNAsraACECzrlIAv5ee2fsPny/96xux78NG6UfNFgIphJTGpif3KA='
#gid=715:
#SERVER_KEYS = 'kscxACtc7A+Q7xncvNj6FBqGRPqoR4P4xLoVDtglYvWwzqPZ9IRKtFt5A6zv5xVXMGA6NFfHOAKSzQLL2gAxAg04GZrWSRfL/OUSt478KH0BkpHquDp846WeIHqPXpjAj/pwrY5QSqpPHAo4KdnIkw=='
#gid=716:
#SERVER_KEYS = 'ksdDACsBomnFq6godbEWdwwGD4h36EYb/z9PyibtI2i6C/b6ThcdfZI/FROrAIOAj8+CMsQinEgWWO0u89gVpJAEoccf2pnHSgKSzQLM2gBDAgA9aAmzmL6vBSnUTTUeAJzRta1yj5ERf+K2/am1MUi4bUaoQ9m0Yg+oY2tT1Ab0TBSNIGmID0xFQ2m3b9yCIk/siQ=='
