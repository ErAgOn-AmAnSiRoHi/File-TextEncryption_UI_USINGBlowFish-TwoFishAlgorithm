#include <algorithm>
#include <array>
#include <string>

#define MAXKEYBYTES 56 // 448 bits max
#define N 16


#if !defined(twofish_twofish_H_)
#define twofish_twofish_H_

class twofish {
private:
  std::array<uint32_t, N + 2> PArray;
  std::array<std::array<uint32_t, 256>, 4> Sboxes;
  uint32_t F(uint32_t x);

public:
  twofish() {}
  twofish(std::string const &key);
  twofish(twofish const &) = delete;

  void initialize(std::string const &key);

  void encrypt(uint32_t &xl, uint32_t &xr);
  void decrypt(uint32_t &xl, uint32_t &xr);
};

#endif // twofish_twofish_H
