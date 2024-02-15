

#include <iostream>

#include "openfhe.h"

using namespace lbcrypto;

// Poly tests
void SHERun();

int main() {
        cout << "Start run_big" << endl;

    int modulus = 61;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(floor(log2(modulus)));
    parameters.SetPlaintextModulus(modulus);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    cout << "m = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() << std::endl;
    std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    // cout << "SecurityLevel : " << cryptoContext -> GetSecurityLevel() << endl;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cryptoContext->KeyGen();
    cout << "KenGen Finished" << endl;
    
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    vector<int64_t> v = {35, 12, 53};
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(v);
    cout << "Plaintext1: " << plaintext1 << endl;
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    

    
    return 0;
}