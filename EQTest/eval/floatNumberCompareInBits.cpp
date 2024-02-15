#include "binfhecontext.h"
#include <string.h>
using namespace lbcrypto;
using std::cout;
using std::endl;
using std::memcpy;

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

void comparePart(BinFHEContext& cc, int idxStart, int idxEnd, LWECiphertext ctNum1[32], LWECiphertext ctNum2[32], LWECiphertext& res) {
    LWECiphertext tmp;
    for (int i = idxStart; i < idxEnd; i++) {
        tmp = cc.EvalBinGate(XOR, ctNum1[i], ctNum2[i]);
        res = cc.EvalBinGate(OR, tmp, res);
    }
}

// num1, num2 to compare
// res is an encryption of 0
// return encryption of 0 if num1 equals num2, 1 otherwise
void compare32ByBits(float num1, float num2, BinFHEContext& cc, ConstLWEPrivateKey sk, LWECiphertext& res) {

    int32_t byte1;
    int32_t byte2;
    memcpy(&byte1, &num1, sizeof(float));
    memcpy(&byte2, &num2, sizeof(float));
        
    cout << "phase 0..." << endl;

    LWECiphertext ctNum1[32];
    LWECiphertext ctNum2[32];

    for (int i = 0; i < 32; i++) {
        ctNum1[i] = cc.Encrypt(sk, ((byte1 & (1 << i)) >> i));
        ctNum2[i] = cc.Encrypt(sk, ((byte2 & (1 << i)) >> i));
    }


    // LWECiphertext tmp;
    // cout << "starting compare one thread..." << endl;
    // std::chrono::steady_clock::time_point t_before_cmp1 = std::chrono::steady_clock::now();

    // for (int i = 0; i < 32; i++) {
    //     LWECiphertext tmp = cc.EvalBinGate(XOR, ctNum1[i], ctNum2[i]);
    //     res = cc.EvalBinGate(OR, tmp, res);
    // }


    // std::chrono::steady_clock::time_point t_after_cmp1 = std::chrono::steady_clock::now();
    // std::chrono::duration<double> time_used_for_cmp1 = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_cmp1 - t_before_cmp1);
    // cout << "time used for cmp is: " << time_used_for_cmp1.count() << endl;


    LWECiphertext res2 = cc.Encrypt(sk, 0);
    int numThreads = 8;
    int elementsPerThread = 32 / numThreads;
    cout << "starting compare with " << numThreads << " threads..." << endl;
    std::chrono::steady_clock::time_point t_before_cmp2 = std::chrono::steady_clock::now();


    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads - 1; i++) {
        int startIndex = i * elementsPerThread; // 计算起始索引
        int endIndex = startIndex + elementsPerThread - 1; // 计算结束索引
        // std::thread myThread(comparePart, std::ref(cc), startIndex, endIndex, std::ref(ctNum1), std::ref(ctNum2), std::ref(res2));
        threads.emplace_back(comparePart, std::ref(cc), startIndex, endIndex, std::ref(ctNum1), std::ref(ctNum2), std::ref(res2));
        // myThread.join();

        // threads.emplace_back(comparePart, cc, startIndex, endIndex, ctNum1, ctNum2, std::ref(res));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::chrono::steady_clock::time_point t_after_cmp2 = std::chrono::steady_clock::now();
    std::chrono::duration<double> time_used_for_cmp2 = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_cmp2 - t_before_cmp2);
    cout << "time used for cmp is: " << time_used_for_cmp2.count() << endl;

    printBits32(byte1);
    printBits32(byte2);
    
    int32_t resByte1 = 0x0000;
    int32_t resByte2 = 0x0000;


    LWEPlaintext resultNum1[32];
    LWEPlaintext resultNum2[32];


    for (int i = 31; i >= 0; i--) {
        cc.Decrypt(sk, ctNum1[i], &resultNum1[i]);
        cc.Decrypt(sk, ctNum2[i], &resultNum2[i]);
        resByte1 = resByte1 << 1;
        resByte1 = resByte1 + ((int32_t) (resultNum1[i] & 1));
        resByte2 = resByte2 << 1;
        resByte2 = resByte2 + ((int32_t) (resultNum2[i] & 1));
    }

    float result1;
    float result2;
    memcpy(&result1, &resByte1, 4);
    memcpy(&result2, &resByte2, 4);
    cout << "result1: " << result1 << endl;
    cout << "result2: " << result2 << endl;


    // return res;
}

int main() {

    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(STD128);

    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;
    
    float num1 = 1.26f;
    float num2 = 1.25f;
        
    LWECiphertext res = cc.Encrypt(sk, 0);


    compare32ByBits(num1, num2, cc, sk, res);
    
    LWEPlaintext resultcmp;

    cc.Decrypt(sk, res, &resultcmp);

    std::cout << "Result of ... = " << resultcmp << std::endl;
    
    return 0;
}