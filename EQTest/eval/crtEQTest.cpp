#include "openfhe.h"
#include <random>
#include <chrono>
#include <cmath>
#include <map>
#include <cstdint>

using namespace lbcrypto;
using std::cout;
using std::endl;
using std::vector;

void run_raw_eq(const int64_t plaintextModulus,
                  const vector<int64_t> compareVector1,
                  const vector<int64_t> compareVector2,
                  const int batchSize);
             
void run_rns_lt(const vector<int64_t> rnsModulusVector,
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int rnsModulusNumber,
             const int batchSize,
             const int64_t p);

void run_rns_eq(const vector<int64_t> rnsModulusVector,
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int rnsModulusNumber,
             const int batchSize);

int main()
{
    // this batchSize only affects how many times the evaluation is done.
    const int batchSize = 1;
    std::default_random_engine dre;
    dre.seed(time(0));

    std::cout << "This program evaluates the time cost of ciphertext comparison. please input the type of eq to use first. `raw_eq` for raw EQ, and 'rns_eq' for RNS-based EQ." << std::endl;
    std::string comparisonType;
    std::cin >> comparisonType;

    if (comparisonType == "raw_eq") {
        std::cout << "For raw EQ, please input the message size, e.g.: for plaintextModulus = 2^16 ≈ 65537, input 16" << std::endl;
        int64_t messageSize, plaintextModulus;
        std::cin >> messageSize;

        if (messageSize == 16) {
            plaintextModulus = 65537;
        } else if (messageSize == 20) {
            plaintextModulus = 1048583;
        } else if (messageSize == 24) {
            plaintextModulus = 16777259;
        } else if (messageSize == 32) {
            plaintextModulus = 4294967311;
        } else if (messageSize == 56) {
            plaintextModulus = 72057594037927936;
        } else {
            std::cout << "inappropriate message size, please restart." << std::endl;
            return 0; 
        }

        vector<int64_t> compareVector1;
        vector<int64_t> compareVector2;
        std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, plaintextModulus);

        for (int i = 0; i < batchSize; i++)
        {
            unsigned int num1 = u(dre) - plaintextModulus / 2;
            unsigned int num2 = u(dre) - plaintextModulus / 2;
            compareVector1.push_back(num1);
            compareVector2.push_back((i & 1) ? num1 : num2);
        }
        run_raw_eq(plaintextModulus, compareVector1, compareVector2, batchSize);
    } else if (comparisonType == "rns_eq") {
        std::cout << "For RNS-based EQ/LT, please input the type(eq/lt), message size and log(ρ), e.g.:eq 16 4" << std::endl;
        std::string rtype; 
        int64_t messageSize, rho, plaintextModulus;
        std::cin >> rtype >> messageSize >> rho;
        vector<int64_t> rnsModulusVector;
        if (messageSize == 16) {
            plaintextModulus = 65537;
            if (rho == 4) {
        	    int64_t tmp[4] = {13, 17, 19, 23};
    	    	rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 4);
            } else if (rho == 6) {
                int64_t tmp[3] = {41, 43, 37};
    	    	rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 3);
            }
        } else if (messageSize == 32) {
            plaintextModulus = 4294967311;
            if (rho == 4) {
                int64_t tmp[8] = {7, 11, 13, 17, 19, 23, 29, 31};
                rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 8);
            } else if (rho == 6) {
                int64_t tmp[5] = {73, 79, 83, 89, 97};
                rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 5);
            }
        } else if (messageSize == 64) {
            plaintextModulus = INT64_MAX;
            if (rho == 4) {
                int64_t tmp[13] = {7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};
                rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 13);
            } else if (rho == 6) {
                int64_t tmp[11] = {53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101};
                rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 11);
            } else if (rho == 8) {
                int64_t tmp[8] = {233, 239, 241, 251, 257, 263, 269, 271};
                rnsModulusVector.insert(rnsModulusVector.begin(), tmp, tmp + 8);
            }
        }
        
        if (rnsModulusVector.size() <= 0) {
            std::cout << "incorrect parameter, please retry." << std::endl;
            return 0;
        }
        const int len = rnsModulusVector.size();


        vector<int64_t> rnsCompareVector1[len];
        vector<int64_t> rnsCompareVector2[len];
        std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, plaintextModulus);

        vector<int64_t> compareVector1;
        vector<int64_t> compareVector2;

        for (int i = 0; i < batchSize; i++)
        {
            unsigned int num1 = u(dre);
            unsigned int num2 = u(dre);
            compareVector1.push_back(num1);
            compareVector2.push_back((i & 1) ? num1 : num2);

            for (int j = 0; j < len; j++)
            {
                int val_1 = (num1 % (rnsModulusVector[j])) - rnsModulusVector[j] / 2;
                int val_2 = (num2 % (rnsModulusVector[j])) - rnsModulusVector[j] / 2;
                
                if (rtype == "lt") {
                    val_1 = abs(val_1);
                    val_2 = abs(val_2);
                }
                
                rnsCompareVector1[j].push_back(val_1);
                rnsCompareVector2[j].push_back(val_2);
            }
        }
        if (rtype == "eq") {
            run_rns_eq(rnsModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize);
        } else {
            run_rns_lt(rnsModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize, plaintextModulus);
        }
        
    }


    // 2^16
    // const int64_t bigPlaintextModulus = 65537;
    // const int rnsModulusVector[] = {41, 43, 37};
    // const int rnsModulusVector[] = {13, 17, 19, 23};


    // 2^20
    // const int64_t bigPlaintextModulus = 1048583;
    // const int rnsModulusVector[] = {23, 29, 31, 37};

    // 2^24
    // const int64_t bigPlaintextModulus = 16777259;
    // const int rnsModulusVector[] = {61, 67, 71, 73};
    // const int rnsModulusVector[] = {11, 13, 17, 19, 23, 29};

    // 2^32
    // const int64_t bigPlaintextModulus = 4294967311;
    // const int rnsModulusVector[] = {65537, 65537};
    // const int rnsModulusVector[] = {73, 79, 83, 89, 97};
    // const int rnsModulusVector[] = {7, 11, 13, 17, 19, 23, 29, 31};

    // --------
    // 2^32 is the max plaintext space for FHE

    // // 2^56
    // const int64_t bigPlaintextModulus = 72057594037927936;
    // const int rnsModulusVector[] = {239, 241, 251, 257, 263, 269, 271};

    // // 2^64
    // const int rnsModulusVector[] = {233, 239, 241, 251, 257, 263, 269, 271};
    // const int rnsModulusVector[] = {7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};

    // const int len = sizeof(rnsModulusVector) / sizeof(rnsModulusVector[0]);
// 10621321031585155072,2909210610636195840,6932654956652199936,517069886044678144,12248659281011030016,11659246075830257664,15783463955705616384,17095016019198570496,3381187541803786240,8911036693395105792,15992104233178281984,8957425486209171456,

    // vector<int64_t> rnsCompareVector641[len] = {
    //     {106,135,107,140,214,6,6,45,20,117,117,61},
    //     {136,80,56,114,228,123,147,162,202,209,234,182},
    //     {132,109,92,234,123,115,30,20,24,82,171,237},
    //     {76,159,9,211,208,58,191,210,250,160,47,64},
    //     {133,128,223,45,1,87,46,154,38,107,174,134},
    //     {228,191,238,180,3,110,103,12,114,125,180,110},
    //     {65,238,101,18,181,134,113,227,38,107,219,31},
    //     {98,156,133,26,146,201,118,149,126,20,74,230}
    // };
    // vector<int64_t> rnsCompareVector642[len] = {
    //     {106,135,107,140,214,6,6,45,20,117,117,61},
    //     {136,80,56,114,228,123,147,162,202,209,234,182},
    //     {132,109,92,234,123,115,30,20,24,82,171,237},
    //     {76,159,9,211,208,58,191,210,250,160,47,64},
    //     {133,128,223,45,1,87,46,154,38,107,174,134},
    //     {228,191,238,180,3,110,103,12,114,125,180,110},
    //     {65,238,101,18,181,134,113,227,38,107,219,31},
    //     {98,156,133,26,146,201,118,149,126,20,74,230}
    // };

    // vector<int64_t> rnsCompareVector1[len];
    // vector<int64_t> rnsCompareVector2[len];
    // std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, bigPlaintextModulus);

    // vector<int64_t> compareVector1;
    // vector<int64_t> compareVector2;

    // for (int i = 0; i < batchSize; i++)
    // {
    //     unsigned int num1 = u(dre);
    //     unsigned int num2 = u(dre);
    //     compareVector1.push_back(num1);
    //     compareVector2.push_back((i & 1) ? num1 : num2);

    //     for (int j = 0; j < len; j++)
    //     {
    //         int val_1 = (num1 % (rnsModulusVector[j])) - rnsModulusVector[j] / 2;
    //         int val_2 = (num2 % (rnsModulusVector[j])) - rnsModulusVector[j] / 2;
            
    //         // for lt
    //         val_1 = abs(val_1);
    //         val_2 = abs(val_2);

    //         // 64
    //         // int val_1 = rnsCompareVector641[j][i] - (rnsModulusVector[j] / 2);
    //         // int val_2 = rnsCompareVector642[j][i] - (rnsModulusVector[j] / 2);
            
    //         rnsCompareVector1[j].push_back(val_1);
    //         rnsCompareVector2[j].push_back(val_2);
    //     }
    // }

    // float f1 = 1.25f;
    // float f2 = 1.25f;
    // int64_t i1, i2;
    // memcpy(&i1, &f1, sizeof(float));
    // memcpy(&i2, &f2, sizeof(float));
    // vector<int64_t> v1 = {i1};
    // vector<int64_t> v2 = {i2};

    // run_eq_raw(bigPlaintextModulus, v1, v2);

    // run_eq_raw(bigPlaintextModulus, compareVector1, compareVector2);
    // run_raw_eq(bigPlaintextModulus, compareVector1, compareVector2, batchSize);
    // run_rns_eq(rnsModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize);
}

void run_raw_eq(const int64_t plaintextModulus,
                  const vector<int64_t> compareVector1,
                  const vector<int64_t> compareVector2,
                  const int batchSize)
{

    cout << "Start raw_eq" << endl;
    // cout << "compareVector1: " << endl;
    // for (int i = 0; i < batchSize; i++)
    // {
    //     cout << compareVector1[i] << " ";
    // }
    // cout << endl;

    // cout << "compareVector2: " << endl;
    // for (int i = 0; i < batchSize; i++)
    // {
    //     cout << compareVector2[i] << " ";
    // }
    // cout << endl;

    double multTime = 0.0;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(16);
    parameters.SetPlaintextModulus(plaintextModulus);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    // cout << "m = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() << std::endl;
    // std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
    //           << std::endl;
    // cout << "SecurityLevel : " << cc -> GetSecurityLevel() << endl;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cout << "KenGen Finished" << endl;

    cc->EvalMultKeyGen(keyPair.secretKey);

    for (int i = 0; i < batchSize; i++)
    {
        vector<int64_t> v(1);
        v[0] = compareVector1[i];
        Plaintext pt1 = cc->MakeCoefPackedPlaintext(v);
        auto ct1 = cc->Encrypt(keyPair.publicKey, pt1);

        v[0] = compareVector2[i];
        Plaintext pt2 = cc->MakeCoefPackedPlaintext(v);
        auto ct2 = cc->Encrypt(keyPair.publicKey, pt2);

        vector<int64_t> vectorOfInts1 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        Plaintext plaintextAllOne = cc->MakeCoefPackedPlaintext(vectorOfInts1);
        auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

        auto cp = cc->EvalSub(ct1, ct2);

        auto res = ciphertextAllOne;

        // cout << "Starting mult..." << endl;
        std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

        for (int x = plaintextModulus - 1; x > 0; x >>= 1)
        {
            if (x & 1)
            {
                res = cc->EvalMult(cp, res);
            }
            cp = cc->EvalMult(cp, cp);
        }
        std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
        std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
        multTime += time_used_for_mul.count();
        // cout << "mult finished..." << endl;
    }

    // Decrypt the result of multiplications
    // Plaintext plaintextMultResult;
    // cryptoContext->Decrypt(keyPair.secretKey, res, &plaintextMultResult);

    // cout << "Plaintext #res: " << plaintextMultResult << endl;

    cout << "time used for mul is: " << multTime << endl;
}


void run_rns_lt(const vector<int64_t> rnsModulusVector,
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int rnsModulusNumber,
             const int batchSize,
             const int64_t p)
{
    vector<int64_t> dif[rnsModulusNumber];
    vector<int64_t> neg[rnsModulusNumber];
     
    for (int i = 0; i < rnsModulusNumber; i++) {
        for(int b = 0; b < batchSize; b++) {
            // cout << compareVector1[i][b] - compareVector2[i][b] / 2 << endl;
            // dif[i].push_back(0);
            dif[i].push_back( compareVector1[i][b] - compareVector2[i][b] );
            neg[i].push_back(0);
        }
    }

    for (int i = -(p-1)/2; i < -1; i++) {
        cout << i << endl;
        for (int j = 0; j < rnsModulusNumber; j++) {
            for (int b = 0; b < batchSize; b++) {
                neg[j][b] = abs( i % rnsModulusVector[j] ) / 2;
            }
        }
        cout << dif << endl;
        run_rns_eq(rnsModulusVector, dif, neg, rnsModulusNumber, batchSize);
    }
}


void run_rns_eq(const vector<int64_t> rnsModulusVector,
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int rnsModulusNumber,
             const int batchSize)
{

    cout << "starting rns comparation..." << endl;
    // cout << "rns modulus: " << endl;
    // for (int i = 0; i < rnsModulusNumber; i++)
    // {
    //     cout << rnsModulusVector[i] << " ";
    // }
    // cout << endl;
    // cout << "compareVector1: " << endl;
    // for (int i = 0; i < rnsModulusNumber; i++)
    // {
    //     for (int j = 0; j < batchSize; j++)
    //     {
    //         cout << compareVector1[i][j] << " ";
    //     }
    //     cout << endl;
    // }
    // cout << endl;

    // cout << "compareVector2: " << endl;
    // for (int i = 0; i < rnsModulusNumber; i++)
    // {
    //     for (int j = 0; j < batchSize; j++)
    //     {
    //         cout << compareVector2[i][j] << " ";
    //     }
    //     cout << endl;
    // }
    // cout << endl;

    using T_CP = Ciphertext<DCRTPoly>;

    // for the ans cp
    vector<vector<T_CP>> resVector(rnsModulusNumber, vector<T_CP>(batchSize, 0));

    double multTime = 0.0;

    for (int i = 0; i < rnsModulusNumber; i++)
    {
        const int modulus = rnsModulusVector[i];
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetMultiplicativeDepth(floor(log2(modulus)));
        parameters.SetPlaintextModulus(modulus);
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        KeyPair<DCRTPoly> keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        vector<int64_t> vectorOfInts1 = {1};
        Plaintext plaintextAllOne = cc->MakeCoefPackedPlaintext(vectorOfInts1);
        auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

        // i compareVector
        // j nums in compareVector[i]
        for (int j = 0; j < batchSize; j++)
        {
            // get compareVector[i][j] and handle one number one time
            vector<int64_t> v(1);
            v[0] = compareVector1[i][j];
            Plaintext pt1 = cc->MakeCoefPackedPlaintext(v);
            auto ct1 = cc->Encrypt(keyPair.publicKey, pt1);

            v[0] = compareVector2[i][j];
            Plaintext pt2 = cc->MakeCoefPackedPlaintext(v);
            auto ct2 = cc->Encrypt(keyPair.publicKey, pt2);
            auto ct = cc->EvalSub(ct1, ct2);

            // Plaintext plaintextResult;
            // cc->Decrypt(keyPair.secretKey, ct, &plaintextResult);
            // cout << "Plaintext ct1 - ct2: " << plaintextResult << endl;

            auto res = ciphertextAllOne;

            // cout << "Starting rns mult, modulus " << i << "\t batch " << j << endl;
            std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

            for (int x = modulus - 1; x > 0; x >>= 1)
            {
                if (x & 1)
                {
                    res = cc->EvalMult(ct, res);
                }
                ct = cc->EvalMult(ct, ct);
            }

            // cout << "mult finished..." << endl;
            std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();

            std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
            multTime += time_used_for_mul.count();

            resVector[i][j] = res;
        }

        // for (int j = 0; j < batchSize; j++)
        // {
        //     Plaintext plaintextResult;
        //     cc->Decrypt(keyPair.secretKey, resVector[i][j], &plaintextResult);
        //     // cout << "Plaintext #" << j << ": " << plaintextResult << endl;
        // }
    }
    cout << "total mul time: " << multTime << endl;
}



