
#include "openfhe.h"
#include <random>
#include <chrono>
#include <cmath>
#include <map>

// #include <bitset>
using namespace lbcrypto;
using std::cout;
using std::endl;
using std::vector;


void run_crt(const int64_t crtModulusVector[],
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int crtModulusNumber,
             const int batchSize);
            

void testle64()
{
    std::default_random_engine dre;
    dre.seed(time(0));

    const int batchSize = 12;

// 65537, 786433, 1179649, 1376257
    // 2^16
    // const int64_t bigPlaintextModulus = 65537;
    // const int crtModulusVector[] = {41, 43, 37};
    // const int crtModulusVector[] = {13, 17, 19, 23};


    // 2^20
    // const int64_t bigPlaintextModulus = 1048583;
    // const int crtModulusVector[] = {23, 29, 31, 37};

    // 2^24
    // const int64_t bigPlaintextModulus = 16777259;
    // const int crtModulusVector[] = {61, 67, 71, 73};
    // const int crtModulusVector[] = {11, 13, 17, 19, 23, 29};

    // 2^32
    const int64_t bigPlaintextModulus = 4294967311;
    const int64_t crtModulusVector[] = {65537, 786433};
    // const int crtModulusVector[] = {73, 79, 83, 89, 97};
    // const int crtModulusVector[] = {7, 11, 13, 17, 19, 23, 29, 31};

    // --------
    // 2^32 is the max plaintext space for FHE

    // // 2^56
    // const int64_t bigPlaintextModulus = 72057594037927936;
    // const int crtModulusVector[] = {239, 241, 251, 257, 263, 269, 271};

    // // 2^64
    // const int crtModulusVector[] = {65537, 786433, 1179649, 1376257};
    // const int crtModulusVector[] = {7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};

    const int len = sizeof(crtModulusVector) / sizeof(crtModulusVector[0]);
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

    vector<int64_t> rnsCompareVector1[len];
    vector<int64_t> rnsCompareVector2[len];
    std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, bigPlaintextModulus);

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
            int val_1 = (num1 % (crtModulusVector[j])) - crtModulusVector[j] / 2;
            int val_2 = (num2 % (crtModulusVector[j])) - crtModulusVector[j] / 2;
            
            // 64
            // int val_1 = rnsCompareVector641[j][i] - (crtModulusVector[j] / 2);
            // int val_2 = rnsCompareVector642[j][i] - (crtModulusVector[j] / 2);
            
            rnsCompareVector1[j].push_back(val_1);
            rnsCompareVector2[j].push_back(val_2);
        }
    }

    // float f1 = 1.25f;
    // float f2 = 1.25f;
    // int64_t i1, i2;
    // memcpy(&i1, &f1, sizeof(float));
    // memcpy(&i2, &f2, sizeof(float));
    // vector<int64_t> v1 = {i1};
    // vector<int64_t> v2 = {i2};

    run_crt(crtModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize);
}


void test64()
{
    std::default_random_engine dre;
    dre.seed(time(0));

    const int batchSize = 32768;

// 65537, 786433, 1179649, 1376257

    // // 2^32 RNS
    // const int crtModulusVector[] = {65537, 786433};

    // 2^32
    const int64_t crtModulusVector[] = {4296540161};

    // // 2^64 RNS
    // const int crtModulusVector[] = {65537, 786433, 1179649, 1376257};

    const int len = sizeof(crtModulusVector) / sizeof(crtModulusVector[0]);


    vector<int64_t> rnsCompareVector1[len];
    vector<int64_t> rnsCompareVector2[len];
    std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, 0xFFFFFFFFFFFFFFFF);

    vector<int64_t> compareVector1;
    vector<int64_t> compareVector2;

    for (int i = 0; i < batchSize; i++)
    {
        int64_t num1 = u(dre);
        int64_t num2 = u(dre);
        compareVector1.push_back(num1);
        compareVector2.push_back((i & 1) ? num1 : num2);

        for (int j = 0; j < len; j++)
        {

            int val_1 = compareVector1[i] % (crtModulusVector[j]);
            int val_2 = compareVector2[i] % (crtModulusVector[j]);
            
            rnsCompareVector1[j].push_back(val_1);
            rnsCompareVector2[j].push_back(val_2);
        }
    }

    run_crt(crtModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize);
}

int main() {
    test64();
}

void run_crt(const int64_t crtModulusVector[],
             const vector<int64_t> compareVector1[],
             const vector<int64_t> compareVector2[],
             const int crtModulusNumber,
             const int batchSize)
{

    cout << "starting CRT comparation..." << endl;
    cout << "CRT modulus: " << endl;
    for (int i = 0; i < crtModulusNumber; i++)
    {
        cout << crtModulusVector[i] << " ";
    }
    cout << endl;
    // cout << "compareVector1: " << endl;
    // for (int i = 0; i < crtModulusNumber; i++)
    // {
    //     for (int j = 0; j < batchSize; j++)
    //     {
    //         cout << compareVector1[i][j] << " ";
    //     }
    //     cout << endl;
    // }
    // cout << endl;

    // cout << "compareVector2: " << endl;
    // for (int i = 0; i < crtModulusNumber; i++)
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
    vector<T_CP> resVector(crtModulusNumber);

    double multTime = 0.0;

    vector<int64_t> vectorOfInts1;
    for (int i = 0; i < batchSize; i++) {
        vectorOfInts1.push_back(1);
    }
    
    for (int i = 0; i < crtModulusNumber; i++)
    {
        const int64_t modulus = crtModulusVector[i];
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetMultiplicativeDepth(floor(log2(modulus)));
        // parametersVector[i].SetMultiplicativeDepth(2);
        parameters.SetPlaintextModulus(modulus);
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        KeyPair<DCRTPoly> keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
    std::cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
        Plaintext plaintextAllOne = cc->MakePackedPlaintext(vectorOfInts1);
        auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

        // i compareVector
        // j nums in compareVector[i]
        vector<int64_t> v1;
        vector<int64_t> v2;
        for (int j = 0; j < batchSize; j++) {
            v1.push_back(compareVector1[i][j]);
            v2.push_back(compareVector2[i][j]);
        }

        Plaintext pt1 = cc->MakePackedPlaintext(v1);
        auto ct1 = cc->Encrypt(keyPair.publicKey, pt1);

        Plaintext pt2 = cc->MakePackedPlaintext(v2);
        auto ct2 = cc->Encrypt(keyPair.publicKey, pt2);
        auto ct = cc->EvalSub(ct1, ct2);

        Plaintext plaintextResult;
        cc->Decrypt(keyPair.secretKey, ct, &plaintextResult);
        // cout << "Plaintext ct1 - ct2: " << plaintextResult << endl;

        auto res = ciphertextAllOne;

        // cout << "Starting CRT mult, modulus " << i << "\t batch " << j << endl;
        std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

        for (int x = modulus - 1; x > 0; x >>= 1)
        {
            if (x & 1)
            {
                res = cc->EvalMult(ct, res);
                cc->Decrypt(keyPair.secretKey, res, &plaintextResult);
                // cout << "Plaintext of modulus :" << modulus << "#" << ": " << plaintextResult << endl;
            }
            ct = cc->EvalMult(ct, ct);
        }

        // cout << "mult finished..." << endl;
        std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();

        std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
        multTime += time_used_for_mul.count();

        resVector[i] = res;

        // Plaintext plaintextResult;
        // cc->Decrypt(keyPair.secretKey, resVector[i], &plaintextResult);
        // cout << "Plaintext #" << ": " << plaintextResult << endl;
    }
    cout << "total mul time: " << multTime << endl;
}
