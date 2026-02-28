/* test_api_xmssmt_sha2_20_2_256.c — API test for XMSSMT-SHA2_20/2_256 */

#define XMSSMT_PARAM_N           32
#define XMSSMT_PARAM_LEN         67
#define XMSSMT_PARAM_TREE_HEIGHT 10
#define XMSSMT_PARAM_BDS_K      2
#define XMSSMT_PARAM_D           2
#define XMSSMT_PARAM_FULL_H      20
#define XMSSMT_PARAM_IDX_BYTES   3
#define XMSSMT_PARAM_OID         0x00000001
#define XMSSMT_PARAM_NAME        "XMSSMT-SHA2_20/2_256"

#define XMSSMT_FN_KEYPAIR  jade_sign_xmssmt_sha2_20_2_256_amd64_ref_keypair
#define XMSSMT_FN_SIGN     jade_sign_xmssmt_sha2_20_2_256_amd64_ref
#define XMSSMT_FN_OPEN     jade_sign_xmssmt_sha2_20_2_256_amd64_ref_open

#define XMSSMT_TEST_BOUNDARY

#include "test_api_xmssmt_common.h"
