/* Milenage (3GPP TS 35.205/206) and the MD5 primitive, the UE side of
 * IMS-AKA. Milenage is built on a single AES-128 block encryption; we
 * borrow libcrypto (already a project dependency via net's OpenSSL) for
 * both AES and MD5 rather than carrying our own. */

#include "ipsecxx.hpp"

#include <openssl/evp.h>

#include <array>
#include <cstring>

namespace ipsec
{

namespace
{

using Block = std::array<uint8_t, 16>;

/* One AES-128 ECB block: out = E_K(in). */
void aes128_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) throw Error("milenage: EVP_CIPHER_CTX_new failed");
    int  len = 0;
    bool ok =
        EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(c, 0) == 1 &&
        EVP_EncryptUpdate(c, out, &len, in, 16) == 1 && len == 16;
    EVP_CIPHER_CTX_free(c);
    if (!ok) throw Error("milenage: AES-128 block encryption failed");
}

Block xorb(const Block& a, const Block& b)
{
    Block r;
    for (int i = 0; i < 16; i++)
        r[i] = a[i] ^ b[i];
    return r;
}

/* Cyclic rotation left by r whole bytes (Milenage rotations are all
 * multiples of 8 bits: r1=64 r2=0 r3=32 r4=64 r5=96). */
Block rotl(const Block& a, int rbytes)
{
    Block r;
    for (int i = 0; i < 16; i++)
        r[i] = a[(i + rbytes) % 16];
    return r;
}

Block block_of(const std::string& s, const char* what)
{
    if (s.size() != 16)
        throw Error(std::string("milenage: ") + what + " must be 16 bytes");
    Block b{};
    std::memcpy(b.data(), s.data(), 16);
    return b;
}

std::string bytes(const uint8_t* p, size_t n)
{
    return std::string(reinterpret_cast<const char*>(p), n);
}

} /* namespace */

std::string aka_opc(const std::string& k, const std::string& op)
{
    Block K = block_of(k, "K"), OP = block_of(op, "OP"), e;
    aes128_block(K.data(), OP.data(), e.data());
    Block opc = xorb(e, OP);
    return bytes(opc.data(), 16);
}

AkaVector aka_milenage(const std::string& k, const std::string& opc,
                       const std::string& rand, const std::string& sqn,
                       const std::string& amf)
{
    Block K    = block_of(k, "K");
    Block OPc  = block_of(opc, "OPc");
    Block RAND = block_of(rand, "RAND");
    if (sqn.size() != 6) throw Error("milenage: SQN must be 6 bytes");
    if (amf.size() != 2) throw Error("milenage: AMF must be 2 bytes");

    /* TEMP = E_K(RAND xor OPc) */
    Block temp;
    {
        Block in = xorb(RAND, OPc);
        aes128_block(K.data(), in.data(), temp.data());
    }

    /* IN1 = SQN || AMF || SQN || AMF */
    Block in1{};
    for (int i = 0; i < 6; i++) {
        in1[i]     = (uint8_t)sqn[i];
        in1[i + 8] = (uint8_t)sqn[i];
    }
    for (int i = 0; i < 2; i++) {
        in1[6 + i]  = (uint8_t)amf[i];
        in1[14 + i] = (uint8_t)amf[i];
    }

    Block c1{}, c2{}, c3{}, c4{};
    c2[15] = 1;
    c3[15] = 2;
    c4[15] = 4; /* c5 (=8) only feeds f5*, unused */

    auto out = [&](const Block& pre, const Block& cst) {
        Block t = xorb(pre, cst), o;
        aes128_block(K.data(), t.data(), o.data());
        return xorb(o, OPc);
    };

    /* OUT1 = E_K( TEMP xor rot(IN1 xor OPc, r1) xor c1 ) xor OPc */
    Block out1 = out(xorb(temp, rotl(xorb(in1, OPc), 8)), c1);
    /* OUT2 = E_K( rot(TEMP xor OPc, r2) xor c2 ) xor OPc  (r2 = 0) */
    Block out2 = out(rotl(xorb(temp, OPc), 0), c2);
    /* OUT3 = E_K( rot(TEMP xor OPc, r3) xor c3 ) xor OPc  (r3 = 32 bits) */
    Block out3 = out(rotl(xorb(temp, OPc), 4), c3);
    /* OUT4 = E_K( rot(TEMP xor OPc, r4) xor c4 ) xor OPc  (r4 = 64 bits) */
    Block out4 = out(rotl(xorb(temp, OPc), 8), c4);

    AkaVector v;
    v.mac = bytes(out1.data(), 8);     /* MAC-A = OUT1[0..7]  */
    v.ak  = bytes(out2.data(), 6);     /* AK    = OUT2[0..5]  */
    v.res = bytes(out2.data() + 8, 8); /* RES   = OUT2[8..15] */
    v.ck  = bytes(out3.data(), 16);
    v.ik  = bytes(out4.data(), 16);
    v.sqn = sqn;
    return v;
}

AkaVector aka_verify(const std::string& k, const std::string& opc,
                     const std::string& rand, const std::string& autn)
{
    if (autn.size() != 16) throw Error("milenage: AUTN must be 16 bytes");
    std::string amf = autn.substr(6, 2);

    /* AK (f5) depends only on K/OPc/RAND, so a run with any SQN recovers
     * it; use it to unmask the real SQN, then run again to check MAC-A. */
    AkaVector   probe = aka_milenage(k, opc, rand, std::string(6, '\0'), amf);
    std::string sqn(6, '\0');
    for (int i = 0; i < 6; i++)
        sqn[i] = (char)((uint8_t)autn[i] ^ (uint8_t)probe.ak[i]);

    AkaVector v = aka_milenage(k, opc, rand, sqn, amf);
    if (v.mac != autn.substr(8, 8))
        throw Error("AKA: AUTN MAC mismatch (authentication failure)", 1);
    return v;
}

std::string md5(const std::string& data)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    EVP_MD_CTX*   c = EVP_MD_CTX_new();
    if (!c) throw Error("md5: EVP_MD_CTX_new failed");
    bool ok = EVP_DigestInit_ex(c, EVP_md5(), nullptr) == 1 &&
              EVP_DigestUpdate(c, data.data(), data.size()) == 1 &&
              EVP_DigestFinal_ex(c, out, &n) == 1;
    EVP_MD_CTX_free(c);
    if (!ok) throw Error("md5: digest failed");
    return std::string(reinterpret_cast<char*>(out), n);
}

} /* namespace ipsec */
