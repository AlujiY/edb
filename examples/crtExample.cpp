/* Copyright (C) 2019-2021 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

// This is a sample program for education purposes only.
// It attempts to show the various basic mathematical
// operations that can be performed on both ciphertexts
// and plaintexts.

#include <iostream>


int ex_gcd(int a, int b, int &x, int &y){
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int d = ex_gcd(b, a % b, y, x);
    y -= (a / b) * x;
    return d;
}

int Chinese_Remainder(int a[],int prime[],int len){
    int i,d,R,y,M,m = 1,sum = 0;
    //计算所有除数的积，也就是所有除数的最小公倍数m
    for(i = 0; i < len; i++)
        m *= prime[i];
    //计算符合所有条件的数
    for(i = 0; i < len; i++){
        M = m / prime[i];//计算除去本身的所有除数的积M
        d = ex_gcd(M,prime[i],R,y);
        sum = (sum + R * M * a[i]) % m;
    }
    return (m + sum % m) % m;//满足所有方程的最小解
}



void test_CRT() {
  int a[] = {13, 17, 19};
  
  int b1[] = {7, 8, 15}; // 2048
  int b2[] = {2, 4, 1}; // 29
  int b[] = {4, 7, 3};
  int ans = Chinese_Remainder(b1, a, 3);
  
  std::cout << ans << std::endl;
}


int EQ_TEST(int num1, int num2, int p) {
  int ans = num1 - num2;
  for(int i = 0; i < p-2; i++) {
    ans = (ans % p) * ((num1 - num2) % p) % p;
    // std::cout << ans << std::endl;
  }
  return ans;
}

void test_EQ_TEST() {
  int ans = EQ_TEST(7, 5, 61);
  std::cout << "final ans: " << ans << std::endl;
  ans = EQ_TEST(37, 37, 61);
  std::cout << "final ans: " << ans << std::endl;
}




int main(int argc, char* argv[]) {
  test_CRT();
}

