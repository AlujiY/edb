#include <iostream>
#include "openfhe.h"

using namespace lbcrypto;



void ckks_demo() {
     uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    // parameters.SetScalingTechnique(scalTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x1 = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt1        = cc->MakeCKKSPackedPlaintext(x1);
    std::vector<double> x2 = {1.0, 2.01, 1.02, 1.03, 3.04, 1.05, 4.06, 1.07};
    Plaintext ptxt2        = cc->MakeCKKSPackedPlaintext(x2);

    // std::cout << "Input x1 - x2: " << ptxt1-ptxt2 << std::endl;

    auto c1 = cc->Encrypt(ptxt1, keys.publicKey);
    auto c2 = cc->Encrypt(ptxt2, keys.publicKey);

    /* Computing f(x) = x^18 + x^9 + 1
   *
   * In the following we compute f(x) with a computation
   * that has a multiplicative depth of 5.
   *
   * The result is correct, even though there is no call to
   * the Rescale() operation.
   */
    auto cRes   = cc->EvalSub(c1, c2);

    Plaintext result;
    std::cout.precision(8);

    cc->Decrypt(cRes, keys.secretKey, &result);
    result->SetLength(batchSize);
    std::cout << "x1 - x2 =  " << result << std::endl;

} 

int main() {
    ckks_demo();
    return 0;
}