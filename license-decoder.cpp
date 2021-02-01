#include "license-decoder.h"
using namespace std;

/* Constants for MD_5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21


/* F, G, H and I are basic MD_5 functions.
*/
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
*/
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
*/
#define FF(a, b, c, d, x, s, ac) { \
    (a) += F ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}


const byte MD_5::PADDING[64] = { 0x80 };
const char MD_5::HEX[16] = {
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f'
};

/* Default construct. */
MD_5::MD_5() {
    reset();
}

/* Construct a MD_5 object with a input buffer. */
MD_5::MD_5(const void* input, size_t length) {
    reset();
    update(input, length);
}

/* Construct a MD_5 object with a string. */
MD_5::MD_5(const string& str) {
    reset();
    update(str);
}

/* Construct a MD_5 object with a file. */
MD_5::MD_5(ifstream& in) {
    reset();
    update(in);
}

/* Return the message-digest */
const byte* MD_5::digest() {
    if (!_finished) {
        _finished = true;
        final();
    }
    return _digest;
}

/* Reset the calculate state */
void MD_5::reset() {

    _finished = false;
    /* reset number of bits. */
    _count[0] = _count[1] = 0;
    /* Load magic initialization constants. */
    _state[0] = 0x67452301;
    _state[1] = 0xefcdab89;
    _state[2] = 0x98badcfe;
    _state[3] = 0x10325476;
}

/* Updating the context with a input buffer. */
void MD_5::update(const void* input, size_t length) {
    update((const byte*)input, length);
}

/* Updating the context with a string. */
void MD_5::update(const string& str) {
    update((const byte*)str.c_str(), str.length());
}

/* Updating the context with a file. */
void MD_5::update(ifstream& in) {
    if (!in)
        return;

    std::streamsize length;
    char buffer[BUFFER_SIZE];
    while (!in.eof()) {
        in.read(buffer, BUFFER_SIZE);
        length = in.gcount();
        if (length > 0)
            update(buffer, length);
    }
    in.close();
}

/* MD_5 block update operation. Continues an MD_5 message-digest
operation, processing another message block, and updating the
context.
*/
void MD_5::update(const byte* input, size_t length) {

    ulong i, index, partLen;

    _finished = false;

    /* Compute number of bytes mod 64 */
    index = (ulong)((_count[0] >> 3) & 0x3f);

    /* update number of bits */
    if ((_count[0] += ((ulong)length << 3)) < ((ulong)length << 3))
        _count[1]++;
    _count[1] += ((ulong)length >> 29);

    partLen = 64 - index;

    /* transform as many times as possible. */
    if (length >= partLen) {

        memcpy(&_buffer[index], input, partLen);
        transform(_buffer);

        for (i = partLen; i + 63 < length; i += 64)
            transform(&input[i]);
        index = 0;

    }
    else {
        i = 0;
    }

    /* Buffer remaining input */
    memcpy(&_buffer[index], &input[i], length - i);
}

/* MD_5 finalization. Ends an MD_5 message-_digest operation, writing the
the message _digest and zeroizing the context.
*/
void MD_5::final() {

    byte bits[8];
    ulong oldState[4];
    ulong oldCount[2];
    ulong index, padLen;

    /* Save current state and count. */
    memcpy(oldState, _state, 16);
    memcpy(oldCount, _count, 8);

    /* Save number of bits */
    encode(_count, bits, 8);

    /* Pad out to 56 mod 64. */
    index = (ulong)((_count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    update(PADDING, padLen);

    /* Append length (before padding) */
    update(bits, 8);

    /* Store state in digest */
    encode(_state, _digest, 16);

    /* Restore current state and count. */
    memcpy(_state, oldState, 16);
    memcpy(_count, oldCount, 8);
}

/* MD_5 basic transformation. Transforms _state based on block. */
void MD_5::transform(const byte block[64]) {

    ulong a = _state[0], b = _state[1], c = _state[2], d = _state[3], x[16];

    decode(block, x, 64);

    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

    _state[0] += a;
    _state[1] += b;
    _state[2] += c;
    _state[3] += d;
}

/* Encodes input (ulong) into output (byte). Assumes length is
a multiple of 4.
*/
void MD_5::encode(const ulong* input, byte* output, size_t length) {

    for (size_t i = 0, j = 0; j < length; i++, j += 4) {
        output[j] = (byte)(input[i] & 0xff);
        output[j + 1] = (byte)((input[i] >> 8) & 0xff);
        output[j + 2] = (byte)((input[i] >> 16) & 0xff);
        output[j + 3] = (byte)((input[i] >> 24) & 0xff);
    }
}

/* Decodes input (byte) into output (ulong). Assumes length is
a multiple of 4.
*/
void MD_5::decode(const byte* input, ulong* output, size_t length) {

    for (size_t i = 0, j = 0; j < length; i++, j += 4) {
        output[i] = ((ulong)input[j]) | (((ulong)input[j + 1]) << 8) |
            (((ulong)input[j + 2]) << 16) | (((ulong)input[j + 3]) << 24);
    }
}

/* Convert byte array to hex string. */
string MD_5::bytesToHexString(const byte* input, size_t length) {
    string str;
    str.reserve(length << 1);
    for (size_t i = 0; i < length; i++) {
        int t = input[i];
        int a = t / 16;
        int b = t % 16;
        str.append(1, HEX[a]);
        str.append(1, HEX[b]);
    }
    return str;
}

/* Convert digest to string value */
string MD_5::toString() {
    return bytesToHexString(digest(), 16);
}


int hash_src(const char* bbsn, const char* cpuid, char* hash_rev) {
    MD_5 md5;
    char* codekey = (char*)"copyright_BOE_2020";
    md5.reset();
    md5.update(codekey);
    md5.update(bbsn);
    md5.update(cpuid);
    memcpy(hash_rev, md5.toString().c_str(), (32 + 1));
    return 0;
}



#ifndef CPUID_H
#define CPUID_H

#ifdef _WIN32
#include <limits.h>
#include <intrin.h>
#pragma comment(lib, "Ws2_32.lib")
typedef unsigned __int32  uint32_t;
#include <intrin.h>
#else
#include <stdint.h>
#include <arpa/inet.h>
#endif
#include <string>


using namespace std;

std::string get_cpu_id_by_asm() {
    unsigned int s1 = 0;
    unsigned int s2 = 0;
    int cpuInfo[4];
    char cpu[17] = { 0 };
#ifdef _WIN32
    __cpuid(cpuInfo, 1);
    snprintf(cpu, sizeof(cpu), "%08X %08X", htonl(cpuInfo[0]), htonl(cpuInfo[3]));
#else
    asm volatile
        (
            "movl $0x01, %%eax; \n\t"
            "xorl %%edx, %%edx; \n\t"
            "cpuid; \n\t"
            "movl %%edx, %0; \n\t"
            "movl %%eax, %1; \n\t"
            : "=m"(s1), "=m"(s2)
            );
    if (0 == s1 && 0 == s2) return "error";
    snprintf(cpu, sizeof(cpu), "%08X%08X", htonl(s2), htonl(s1));
#endif
    return std::string(cpu);
}
#endif // CPUID_H


///sys/class/dmi/id/board_serial 
std::string get_baseboard_serial_number() {
#ifdef __linux__ 
    std::ifstream sysfile("/sys/class/dmi/id/board_serial");
    std::string content((std::istreambuf_iterator<char>(sysfile)), (std::istreambuf_iterator<char>()));
    //std::cout << "board_serial is :"<<content << std::endl;
    sysfile.close();
#endif // __linux__ 
#ifdef _WIN32
    // not implement
#endif // _WIN32

    return content;
}




std::vector<std::string> split_lic_file_content(const std::string lic_file_name) {
    std::ifstream licfile(lic_file_name);
    std::string delimiter = ";";
    size_t pos = 0;
    std::string token;
    std::string content((std::istreambuf_iterator<char>(licfile)),
        (std::istreambuf_iterator<char>()));
    std::vector<std::string> lic_con;
    while ((pos = content.find(delimiter)) != std::string::npos)
    {
        token = content.substr(0, pos);
        token.erase(std::remove(token.begin(), token.end(), '\n'), token.end());
        lic_con.push_back(token);
        //std::cout << "+++++++++++++"<<std::endl<< token << std::endl;
        content.erase(0, pos + delimiter.length());
        content.erase(std::remove(content.begin(), content.end(), '\n'), content.end());
    }
    //std::cout << "---------------"<<std::endl<< content << std::endl;
    lic_con.push_back(content);
    licfile.close();
    return lic_con;
}

int verify_license(std::string result_string_json) {
    rapidjson::Document doc;
    doc.Parse(result_string_json.c_str());
    /*{
        "aud": "Consumer",
        "exp": 1641876853,
        "jti": "20210111045413632987",
        "iat": 1610340853,
        "iss": "https://www.cloud.boe.com",
        "nbf": 1610340853,
        "sub": "lic",
        "productCode": "AI01A00301",
        "productName": "AI01A00301",
        "productVersion": "ALL_SUPPORTED",
        "licenseType": "SDK",
        "grantedNum": 999,
        "extension": {
            "enable": "false",
            "machineID": "111111"
        }
    }*/
    /*char writeBuffer[65536];
    rapidjson::FileWriteStream os(stdout, writeBuffer, sizeof(writeBuffer));
    rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);
    doc.Accept(writer);*/

    static const char* kTypeNames[] = { "Null", "False", "True", "Object", "Array", "String", "Number" };
    uint64_t exp = 0; std::string lic_machine_id; bool thismachine_isenabled = false;
    for (rapidjson::Value::ConstMemberIterator itr = doc.MemberBegin(); itr != doc.MemberEnd(); ++itr)
    {
        std::string docname(itr->name.GetString());
        //std::cout<<"Type of member "<< docname<< "is "<<kTypeNames[itr->value.GetType()]<<std::endl;

        if (docname == "extension" && kTypeNames[itr->value.GetType()] == "Object") // get extension and machineID
        {
            if (std::string(itr->value["enable"].GetString()) == "true") thismachine_isenabled = true;
            /*if (not thismachine_isenabled)
            {
                std::cerr << "this machine is not enabled !" << std::endl;
                return 1;
            }*/
            lic_machine_id = std::string(itr->value["machineID"].GetString());

        }
        else if (docname == "exp" && kTypeNames[itr->value.GetType()] == "Number") exp = itr->value.GetInt64();
    }


    char machineID_get[32 + 1] = { 0 };
    if (hash_src(get_baseboard_serial_number().c_str(), get_cpu_id_by_asm().c_str(), machineID_get)) {
        std::cerr << "hash_src error!" << std::endl;
        return 2;
    }

    if (lic_machine_id != machineID_get) {
        std::cerr << "machine is changed!" << std::endl;
        return 3;
    }
    using namespace std::chrono;
    seconds ms = duration_cast<seconds>(system_clock::now().time_since_epoch());
    if (exp < ms.count()) {
        // now 1610434876
        std::cerr << "this license is expired!" << std::endl;
        return 4;
    }

    std::cout << " exp is :" << exp << " lic_machine_id is :" << lic_machine_id << " thismachine_isenabled is " << thismachine_isenabled << std::endl;
    std::cout << " cpuid is : " << get_cpu_id_by_asm() << std::endl;
    std::cout << " baseboard-serial-number is : " << get_baseboard_serial_number() << std::endl;
    std::cout << " get_baseboard_serial_number is : " << machineID_get << std::endl;
    std::cout << " license good! enjoy." << std::endl;
    return 0;
}


int decode_lic(std::string lic_file_name) {
    std::vector<std::string> lics = split_lic_file_content(lic_file_name);
    if (3 - lics.size()) {
        std::cerr << "Incorrect license file content ! " << std::endl;
        return -1;
    }
    std::string result = DecodeLicense((char*)lics[0].c_str(), (char*)lics[1].c_str(), (char*)lics[2].c_str());
    if (result.find("ERROR") != std::string::npos || result.find("error") != std::string::npos)
    {
        std::cerr << "+++++++++" << std::endl << result << std::endl << "+++++++++" << std::endl << std::endl;
        return -2;
    }
    if (verify_license(result)) {
        std::cerr << "+++++++++" << "license file verify faild machieid or expdate is not valid!" << "+++++++++" << std::endl << std::endl;
        return -3;
    }
    return 0;
}

void gen_current_hw_finger() {
    char machineID_get[32 + 1] = { 0 };
    if (hash_src(get_baseboard_serial_number().c_str(), get_cpu_id_by_asm().c_str(), machineID_get)) {
        std::cerr << "hash_src error!" << std::endl;
        return;
    }
#ifdef DEBUG
    std::cout << "only for debug use!!!" << std::endl;
    std::cout << machineID_get << std::endl;
    std::cout << "only for debug use!!!" << std::endl;
#endif // DEBUG


}

#ifdef __cplusplus
extern "C" {
#endif
    int decode_lic(char* lic_file_name) {
        return decode_lic(std::string(lic_file_name));
    }

#ifdef __cplusplus
}
#endif