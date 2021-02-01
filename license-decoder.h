#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <string.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/ostreamwrapper.h"
#include "rapidjson/filewritestream.h"
#include <rapidjson/prettywriter.h>
#ifdef __cplusplus
extern "C" {
#endif


	extern char* DecodeLicense(char* p0, char* p1, char* p2);

#ifdef __cplusplus
}
#endif
/* Type define */
typedef unsigned char byte;
typedef unsigned long ulong;
class MD_5
{
public:
	MD_5();
	MD_5(const void* input, size_t length);
	MD_5(const std::string& str);
	MD_5(std::ifstream& in);
	void update(const void* input, size_t length);
	void update(const std::string& str);
	void update(std::ifstream& in);
	const byte* digest();
	std::string toString();
	void reset();
private:
	void update(const byte* input, size_t length);
	void final();
	void transform(const byte block[64]);
	void encode(const ulong* input, byte* output, size_t length);
	void decode(const byte* input, ulong* output, size_t length);
	std::string bytesToHexString(const byte* input, size_t length);

	/* class uncopyable */
	MD_5(const MD_5&);
	MD_5& operator=(const MD_5&);
private:
	ulong _state[4];	/* state (ABCD) */
	ulong _count[2];	/* number of bits, modulo 2^64 (low-order word first) */
	byte _buffer[64];	/* input buffer */
	byte _digest[16];	/* message digest */
	bool _finished;		/* calculate finished ? */

	static const byte PADDING[64];	/* padding for calculate */
	static const char HEX[16];
	static const size_t BUFFER_SIZE = 1024;
};




std::string get_cpu_id_by_asm();
std::string get_baseboard_serial_number();
//dmidecode -s baseboard-serial-number /9D41W63/CNPE10007O071Y/
//dmidecode -s system-uuid 4C4C4544-0044-3410-8031-B9C04F573633
int hash_src(const char* bbsn, const char* cpuid, char* hash_rev);
void gen_current_hw_finger();
int decode_lic(std::string );