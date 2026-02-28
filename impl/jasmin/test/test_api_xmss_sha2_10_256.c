/* test_api_xmss_sha2_10_256.c — API test for XMSS-SHA2_10_256 */

#define XMSS_PARAM_N           32
#define XMSS_PARAM_LEN         67
#define XMSS_PARAM_TREE_HEIGHT 10
#define XMSS_PARAM_BDS_K      2
#define XMSS_PARAM_OID         0x00000001
#define XMSS_PARAM_NAME        "XMSS-SHA2_10_256"

#define XMSS_FN_KEYPAIR  jade_sign_xmss_sha2_10_256_amd64_ref_keypair
#define XMSS_FN_SIGN     jade_sign_xmss_sha2_10_256_amd64_ref
#define XMSS_FN_OPEN     jade_sign_xmss_sha2_10_256_amd64_ref_open

#include "test_api_xmss_common.h"
