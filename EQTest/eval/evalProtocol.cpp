#include "openfhe.h"
#include <random>
#include <chrono>
#include <cmath>
#include <map>
#include <cstdint>

using namespace lbcrypto;
using T_CP = Ciphertext<DCRTPoly>;

using std::cout;
using std::cin;
using std::endl;
using std::string;
using std::vector;

const int64_t plaintextModulus = 4294967311;
const int rnsModulusNumber = 8;
const vector<int64_t> rnsModulusVector = {7, 11, 13, 17, 19, 23, 29, 31};
CryptoContext<DCRTPoly> cc[rnsModulusNumber];
KeyPair<DCRTPoly> keyPair[rnsModulusNumber];


void evalProtocol(int tau, int numEq, int numLT, string aggr);
T_CP rns_eq(const T_CP &op1, const T_CP &op2, int q);
T_CP rns_lt(const T_CP &op1, const T_CP &op2, int q);


void initCcNoSIMD() {
    for (int i = 0; i < rnsModulusNumber; i++) {
        const int modulus = rnsModulusVector[i];
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetMultiplicativeDepth(floor(log2(modulus)) + 4);
        parameters.SetPlaintextModulus(modulus);
        cc[i] = GenCryptoContext(parameters);
        cc[i]->Enable(PKE);
        cc[i]->Enable(KEYSWITCH);
        cc[i]->Enable(LEVELEDSHE);
        keyPair[i] = cc[i]->KeyGen();
        cc[i]->EvalMultKeyGen(keyPair[i].secretKey);
    }
    cout << "CryptoContext and KeyPair generatation is done." << endl;
}

int main() {
    cout << "This program evals the communicataion cost of the Private Database Query protocol." << endl
         << "Please input record number and whether using SIMD. e.g.: 10 none  or 32768 SIMD" << endl;
    int tau;
    string useSIMD;
    cin >> tau >> useSIMD;
    cout << "Please input the required query condition number(number of equality query conditions, number of order query conditions) and aggregation type(`none` for no aggregation)." << endl;
    int numEq, numLT;
    string aggr;
    cin >> numEq >> numLT >> aggr;
    if (useSIMD == "none") {
        // double multTime = 0.0;
        evalProtocol(tau, numEq, numLT, aggr);
    }
    return 0;
}

void evalProtocol(int tau, int numEq, int numLT, string aggr) {
    
    int columnNum = numEq + numLT + 1;
    if (aggr != "none") {
        columnNum++;
    }
    
    int64_t ptRnsData[tau][columnNum][rnsModulusNumber];
    T_CP ctRnsData[tau][columnNum][rnsModulusNumber];
    
    
    vector<int64_t> tmp(1);
    vector<int64_t> vectorOfInts1 = {1};
    vector<int64_t> vectorOfInts0 = {0};

    // Generate random data and encrypt.
    {
        std::default_random_engine dre;
        dre.seed(time(0));
        std::uniform_int_distribution<int64_t> u = std::uniform_int_distribution<int64_t>(0, plaintextModulus);

        initCcNoSIMD();
        for (int i = 0; i < tau; i++) {
            for (int j = 0; j < columnNum; j++) {
                int64_t num = u(dre);
                for (int q = 0; q < rnsModulusNumber; q++) {
                    int64_t rns_val = (num % (rnsModulusVector[q])) - rnsModulusVector[q] / 2;
                    ptRnsData[i][j][q] = rns_val;
                    tmp[0] = rns_val;
                    Plaintext ptrns_val = cc[q] -> MakeCoefPackedPlaintext(tmp);
                    auto ct = cc[q] -> Encrypt(keyPair[q].publicKey, ptrns_val);
                    ctRnsData[i][j][q] = ct;
                }
            }
        }
        cout << "Data generation and encryption is done." << endl;
    }

    // Generate the query. Suppose the query condition is just the same as the first record.
    T_CP ctQuery[numEq + numLT][rnsModulusNumber];
    {
        for (int j = 0; j < numEq + numLT; j++) {
            for (int q = 0; q < rnsModulusNumber; q++) {
                tmp[0] = ptRnsData[0][j][q];
                Plaintext pt = cc[q] -> MakeCoefPackedPlaintext(tmp);
                auto ct = cc[q] -> Encrypt(keyPair[q].publicKey, pt);
                ctQuery[j][q] = ct;
            }
        }
        cout << "Query generation and encryption is done." << endl;
    }
        
    // Process the query conditions.
    T_CP X[tau][rnsModulusNumber];
    for (int i = 0; i < tau; i++) {
        for (int q = 0; q < rnsModulusNumber; q++) {
            Plaintext ptOne = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts1);
            X[i][q] = cc[q] -> Encrypt(keyPair[q].publicKey, ptOne);
        }
    }
    std::chrono::steady_clock::time_point t_query_before = std::chrono::steady_clock::now();
    {
        for (int i = 0; i < tau; i++) {
      
            for (int j = 0; j < numEq + numLT; j++) {
                for (int q = 0; q < rnsModulusNumber; q++) {
                    T_CP cur;
                    if ( j < numEq) {
                        cur = rns_eq(ctRnsData[i][j][q], ctQuery[j][q], q);
                    } else {
                        cur = rns_eq(ctRnsData[i][j][q], ctQuery[j][q], q);
                    }
                    X[i][q] = cc[q] -> EvalMult(X[i][q], cur);
                }
            }
        }
    }
    std::chrono::steady_clock::time_point t_query_after = std::chrono::steady_clock::now();
    cout << "Query conditions processed." << endl;
    std::chrono::duration<double> time_used_for_query = std::chrono::duration_cast<std::chrono::duration<double>>(t_query_after - t_query_before);
    cout << "Query processing time: " << time_used_for_query.count() << endl;


    // aggr
    T_CP Group[tau][tau][rnsModulusNumber];
    T_CP aggregationVaule[tau][rnsModulusNumber];
    if (aggr != "none") 
    {

        for (int q = 0; q < rnsModulusNumber; q++) {
            for (int i1 = 0; i1 < tau; i1++) {
                Plaintext plaintextAllOne = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts1);
                auto ciphertextAllOne = cc[q] -> Encrypt(keyPair[q].publicKey, plaintextAllOne);
                Group[i1][i1][q] = ciphertextAllOne;
                for (int i2 = i1; i2 < tau; i2++) {
                    auto r = rns_eq(ctRnsData[i1][0][q], ctRnsData[i2][0][q], q);
                    Group[i1][i2][q] = r;
                    Group[i2][i1][q] = r;
                }
            }
        }

        std::chrono::steady_clock::time_point t_aggr_before = std::chrono::steady_clock::now();
        if (aggr == "sum") {
            for (int i = 0; i < tau; i++) {
                for (int q = 0; q < rnsModulusNumber; q++) {
                    Plaintext ptZero = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts0);
                    auto ctZero = cc[q] -> Encrypt(keyPair[q].publicKey, ptZero);
                    aggregationVaule[i][q] = ctZero;
                }
            }

            for (int i1 = 0; i1 < tau; i1++) {
                for (int i2 = 0; i2 < tau; i2++) {
                    for (int q = 0; q < rnsModulusNumber; q++) {
                        auto tmp = cc[q] -> EvalMult(ctRnsData[i2][numEq+numLT][q], Group[i1][i2][q]);
                        aggregationVaule[i1][q] = cc[q] -> EvalAdd(aggregationVaule[i1][1], tmp);
                    }
                }
            }
        } else if (aggr == "count") {
            for (int i = 0; i < tau; i++) {
                for (int q = 0; q < rnsModulusNumber; q++) {
                    Plaintext ptZero = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts0);
                    auto ctZero = cc[q] -> Encrypt(keyPair[q].publicKey, ptZero);
                    aggregationVaule[i][q] = ctZero;
                }
            }

            for (int i1 = 0; i1 < tau; i1++) {
                for (int i2 = 0; i2 < tau; i2++) {
                    for (int q = 0; q < rnsModulusNumber; q++) {
                        aggregationVaule[i1][q] = cc[q] -> EvalAdd(aggregationVaule[i1][1], Group[i1][i2][q]);
                    }
                }
            }
        }
        std::chrono::steady_clock::time_point t_aggr_after = std::chrono::steady_clock::now();
        cout << "Aggregation processed." << endl;
        std::chrono::duration<double> time_used_for_aggr = std::chrono::duration_cast<std::chrono::duration<double>>(t_aggr_after - t_aggr_before);
        cout << "Query processing time: " << time_used_for_aggr.count() << endl;

    }


    // retrieval
    T_CP result[tau][rnsModulusNumber];
    {
        T_CP value[tau][rnsModulusNumber];
        if (aggr == "none") {
            for (int i = 0; i < tau; i++) {
                for (int q = 0; q < rnsModulusNumber; q++) {
                    value[i][q] = ctRnsData[i][numEq+numLT][q];
                }
            }
        }

        for (int i = 0; i < tau; i++) {
            for (int q = 0; q < rnsModulusNumber; q++) {
                result[i][q] = cc[q] -> EvalMult(value[i][q], X[i][q]);
            }
        }

        cout << "Retrieval finished." << endl;
    }
}


T_CP rns_eq(const T_CP &op1, const T_CP &op2, int q) {

    vector<int64_t> vectorOfInts1 = {1};
    Plaintext ptOne = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts1);
    auto res = cc[q] -> Encrypt(keyPair[q].publicKey, ptOne);
    auto ct = cc[q] -> EvalSub(op1, op2);
    for (int x = rnsModulusVector[q] - 1; x > 0; x >>= 1)
    {
        if (x & 1)
        {
            res = cc[q]->EvalMult(ct, res);
        }
        ct = cc[q]->EvalMult(ct, ct);
    }
    return res;
}

T_CP rns_lt(const T_CP &op1, const T_CP &op2, int q) {
    vector<int64_t> vectorOfInts0 = {0};
    Plaintext plaintextZero = cc[q] -> MakeCoefPackedPlaintext(vectorOfInts0);
    auto res = cc[q] -> Encrypt(keyPair[q].publicKey, plaintextZero);
    auto op = cc[q] -> EvalSub(op1, op2);
    
    vector<int64_t> tmp(1);
    for (int i = -(rnsModulusVector[q] - 1) / 2; i < -1; i++) {
        tmp[0] = i;
        Plaintext pt = cc[q] -> MakeCoefPackedPlaintext(tmp);
        auto ctOp = cc[q] -> Encrypt(keyPair[q].publicKey, pt);
        auto cur = rns_eq(ctOp, op, q);
        res = cc[q] -> EvalAdd(cur, res);
    }
    return res;
}