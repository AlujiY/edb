/*
  Simple example for BGVrns (integer arithmetic)
 */

#include "openfhe.h"
#include <random>
#include <chrono>
#include <cmath>
#include <map>

// #include <bitset>
using namespace lbcrypto;
using std::vector;
using std::cout;
using std::endl;

inline void printBits16(int32_t t) {
    for (int i = 16 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

inline void printBits32(int32_t t) {
    for (int i = 32 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

inline void printBits64(int64_t t) {
    for (int i = 64 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

void compare32ByBFVBatch(float* nums1, float* nums2, CryptoContext<DCRTPoly>& cc, KeyPair<DCRTPoly> keyPair, int batchSize) {

    // for (int i = 0; i < batchSize; i++ ) {
    //     cout << nums1[i] << "\t";
    // }
    // cout << endl;
    
    // for (int i = 0; i < batchSize; i++ ) {
    //     cout << nums2[i] << "\t";
    // }
    // cout << endl;
    
    // num to compare is converted into two 16bit byte.
    int16_t byte1[batchSize][2];
    int16_t byte2[batchSize][2];

    vector<int64_t> v1[2];
    vector<int64_t> v2[2];

    for (int i = 0; i < batchSize; i++) {
        memcpy(byte1[i], &nums1[i], 4);
        memcpy(byte2[i], &nums2[i], 4);

        v1[0].push_back(byte1[i][0]);
        v1[1].push_back(byte1[i][1]);
        v2[0].push_back(byte2[i][0]);
        v2[1].push_back(byte2[i][1]);
        // cout << byte1[i][0] << "\t";
        // cout << byte2[i][0] << "\t";
    }

    Plaintext pt1[2], pt2[2];
    Ciphertext<DCRTPoly> ct1[2], ct2[2];

    pt1[0] = cc->MakePackedPlaintext(v1[0]);
    cout << pt1[0] << endl;
    ct1[0] = cc->Encrypt(keyPair.publicKey, pt1[0]);

    pt2[0] = cc->MakePackedPlaintext(v2[0]);
    cout << pt2[0] << endl;
    ct2[0] = cc->Encrypt(keyPair.publicKey, pt2[0]);

    pt1[1] = cc->MakePackedPlaintext(v1[1]);
    cout << pt1[1] << endl;
    ct1[1] = cc->Encrypt(keyPair.publicKey, pt1[1]);

    pt2[1] = cc->MakePackedPlaintext(v2[1]);
    cout << pt2[1] << endl;
    ct2[1] = cc->Encrypt(keyPair.publicKey, pt2[1]);



    vector<int64_t> vectorOfInts1;
    for (int i = 0; i < batchSize; i++) {
        vectorOfInts1.push_back(1);
    }

    Plaintext plaintextAllOne = cc->MakePackedPlaintext(vectorOfInts1);
    auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

    auto cp0 = cc->EvalSub(ct1[0], ct2[0]);
    auto cp1 = cc->EvalSub(ct1[1], ct2[1]);

    auto res0 = ciphertextAllOne;
    auto res1 = ciphertextAllOne;

    cout << "Starting mult..." << endl;
    std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

    for (int x = 65537 - 1; x > 0; x >>= 1) {
        if(x&1) {
            res0 = cc->EvalMult(cp0, res0);
            res1 = cc->EvalMult(cp1, res1);
        }
        cp0 = cc->EvalMult(cp0, cp0);
        cp1 = cc->EvalMult(cp1, cp1);
    }

    // res = res0 + res1 - res0*res1
    // => res = 0 if and only if res0 = res1 = 0,
    // res = 0 <=> float1 = float2
    auto tmp = cc->EvalMult(res0, res1);
    auto res = cc->EvalAdd(res0, res1);
    res = cc->EvalSub(res, tmp);

    
    std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
    cout << "mult finished..." << endl;

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cc->Decrypt(keyPair.secretKey, res, &plaintextMultResult);

    cout << "Plaintext #res: " << plaintextMultResult << endl;
    std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
    cout << "total mul time: " << time_used_for_mul.count() << endl;

}




// do 32 bits float number comparation as two 16bits Integer
void compare32ByBFV(float num1, float num2, CryptoContext<DCRTPoly>& cc, KeyPair<DCRTPoly> keyPair) {
    
    // num to compare is converted into two 16bit byte.
    int16_t byte1[2] = {0};
    memcpy(byte1, &num1, 4);

    vector<int64_t> v1 = {byte1[0], byte1[1]};

    int16_t byte2[2] = {0};
    memcpy(byte2, &num2, 4);

    vector<int64_t> v2 = {byte2[0], byte2[1]};


    Plaintext pt1 = cc->MakePackedPlaintext(v1);
    cout << "Plaintext1: " << pt1 << endl;
    auto ct1 = cc->Encrypt(keyPair.publicKey, pt1);

    Plaintext pt2 = cc->MakePackedPlaintext(v2);
    cout << "Plaintext2: " << pt2 << endl;
    auto ct2 = cc->Encrypt(keyPair.publicKey, pt2);


    vector<int64_t> vectorOfInts1 = {1, 1};
    Plaintext plaintextAllOne = cc->MakePackedPlaintext(vectorOfInts1);
    auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

    auto cp = cc -> EvalSub(ct1, ct2);

    auto res = ciphertextAllOne;

    cout << "Starting mult..." << endl;
    std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

    for (int x = 65537 - 1; x > 0; x >>= 1) {
        if(x&1) {
            res = cc -> EvalMult(cp, res);
        }
        cp = cc -> EvalMult(cp, cp);
    }
    std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
    cout << "mult finished..." << endl;

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cc->Decrypt(keyPair.secretKey, res, &plaintextMultResult);

    cout << "Plaintext #res: " << plaintextMultResult << endl;
    std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);

}




int main() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(17);
    parameters.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    cout << "m = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    // cout << "SecurityLevel : " << cc -> GetSecurityLevel() << endl;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cout << "KenGen Finished" << endl;
    
    cc->EvalMultKeyGen(keyPair.secretKey);

    // 2^16
    // const int plaintextModulus = 65537;
    // const int crtModulusVector[] = {41, 43, 37};

    const int batchSize = 12;

    float nums1[batchSize];
    float nums2[batchSize];

    std::default_random_engine dre;
    dre.seed(time(0));
    std::uniform_real_distribution<float> u = std::uniform_real_distribution<float>(0, 5719451); // upper bound, just randomly typed

    for (int i = 0; i < batchSize; i++) {
        nums1[i] = u(dre);
        if (i&1) {
            nums2[i] = nums1[i];
        } else {
            nums2[i] = u(dre);
        }
    }

    compare32ByBFVBatch(nums1, nums2, cc, keyPair, 12);

    

}
