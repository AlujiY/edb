
#define PROFILE

#include <iostream>

#include "openfhe.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    std::cout << "\nThis code demonstrates the use of the BFVrns scheme for "
                 "homomorphic multiplication. "
              << std::endl;
    std::cout << "This code shows how to auto-generate parameters during run-time "
                 "based on desired plaintext moduli and security levels. "
              << std::endl;
    std::cout << "In this demonstration we use three input plaintext and show "
                 "how to both add them together and multiply them together. "
              << std::endl;

    // benchmarking variables
    TimeVar t;
    double processingTime(0.0);

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(9);
    // parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning key generation (used for source data)..." << std::endl;

    TIC(t);

    keyPair = cryptoContext->KeyGen();

    processingTime = TOC(t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Running key generation for homomorphic multiplication "
                 "evaluation keys..."
              << std::endl;

    TIC(t);

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    processingTime = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms"
              << std::endl;

    // cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vectorOfInts1;

    std::vector<int64_t> vectorOfInts2;

    int MAX_BATCH_NUMBER = 16385;

    for (int i = 0; i < MAX_BATCH_NUMBER; i++) {
        vectorOfInts1.push_back(7);
        vectorOfInts2.push_back(2);
    }
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    std::cout << "\nOriginal Plaintext #1: \n";
    // std::cout << plaintext1 << std::endl;

    std::cout << "\nOriginal Plaintext #2: \n";
    // std::cout << plaintext2 << std::endl;


    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning encryption of all plaintexts... ";

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;

    TIC(t);

    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext1));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext2));

    processingTime = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nAverage encryption time: " << processingTime / 2 << "ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 2 ciphertexts
    ////////////////////////////////////////////////////////////

    TIC(t);

    auto ciphertextMult = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    processingTime = TOC(t);
    std::cout << "\nTotal time of multiplying 2 ciphertexts using EvalMult w/ "
                 "relinearization: "
              << processingTime << "ms" << std::endl;

    Plaintext plaintextDecMult;

    TIC(t);

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDecMult);

    processingTime = TOC(t);
    std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;

    plaintextDecMult->SetLength(plaintext1->GetLength());

    // std::cout << "\nResult of homomorphic multiplication of ciphertexts #1 and #2: \n";
    // std::cout << plaintextDecMult << std::endl;

}