#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main() {

    std::cout << "This program is made to test the size of ciphertext for different parameters. Please input the plaintextModulus and multiplicative Depth. e.g.: 17 5." << std::endl;
    uint64_t plaintextModulus;
    uint64_t multiplicativeDepth; 
    std::cin >> plaintextModulus >> multiplicativeDepth;

    CCParams<CryptoContextBFVRNS> parameters;
    // p: 2^4 17        depth: 5 
    // p: 2^6 67        depth: 7
    // p: 2^16 65537    depth: 18
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << "\nThe cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "The key pair has been generated." << std::endl;

    // Serialize the public key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return 1;
    }
    std::cout << "The public key has been serialized." << std::endl;

    // Serialize the secret key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been serialized." << std::endl;

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "The eval mult keys have been generated." << std::endl;

    // Serialize the relinearization (evaluation) key for homomorphic
    // multiplication
    std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval mult keys to "
                         "key-eval-mult.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval mult keys have been serialized." << std::endl;

        emkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval mult keys" << std::endl;
        return 1;
    }

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    std::cout << "The rotation keys have been generated." << std::endl;

    // Serialize the rotation keyhs
    std::ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out | std::ios::binary);
    if (erkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval rotation keys to "
                         "key-eval-rot.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval rotation keys have been serialized." << std::endl;

        erkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval rotation keys" << std::endl;
        return 1;
    }

    // Sample Program: Step 3: Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext1               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext2               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
    // Third plaintext vector is encoded
    std::vector<int64_t> vectorOfInts3 = {0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext3               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);


    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

    std::cout << "The plaintexts have been encrypted." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext2.txt", ciphertext2, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 2 to ciphertext2.txt" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext3.txt", ciphertext3, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 3 to ciphertext3.txt" << std::endl;
        return 1;
    }
    std::cout << "The third ciphertext has been serialized." << std::endl
            << "The size of serialized ciphertext can be seen in the `demoData` folder." << std::endl;

    return 0;
}