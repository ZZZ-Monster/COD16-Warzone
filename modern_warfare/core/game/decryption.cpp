#include "sdk.h"
#include "..\driver\driver.h"
#include "offsets.h"

namespace decryption {
	uintptr_t get_client_info() {
		uintptr_t imageBase = sdk::module_base;
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = driver::read<uintptr_t>(imageBase + 0x1DD5B028);
		if (!rbx)
			return rbx;
		rcx = sdk::peb;;            //mov byte ptr [rsp+0x50], 0x18
		rdx = imageBase;
		rax = rbx;              //mov rax, rbx
		rax >>= 0x11;           //shr rax, 0x11
		rbx ^= rax;             //xor rbx, rax
		rcx = rbx;              //mov rcx, rbx
		rcx >>= 0x22;           //shr rcx, 0x22
		rcx ^= rbx;             //xor rcx, rbx
		rcx -= rdx;             //sub rcx, rdx
		rax = rcx;              //mov rax, rcx
		rax >>= 0x18;           //shr rax, 0x18
		rcx ^= rax;             //xor rcx, rax
		rbx = rcx;              //mov rbx, rcx
		rax = 0;                //and rax, 0xFFFFFFFFC0000000
		rbx >>= 0x30;           //shr rbx, 0x30
		rax = _rotl64(rax, 0x10);               //rol rax, 0x10
		rbx ^= rcx;             //xor rbx, rcx
		rax ^= driver::read<uintptr_t>(imageBase + 0x73440FA);             //xor rax, [0x0000000005059017]
		rax = (_byteswap_uint64)(rax);                 //bswap rax
		rbx *= driver::read<uintptr_t>(rax + 0xb);              //imul rbx, [rax+0x0B]
		rax = 0xB0A1D51ABBE53429;               //mov rax, 0xB0A1D51ABBE53429
		rbx *= rax;             //imul rbx, rax
		rax = 0x5F536B6BDB3EE14E;               //mov rax, 0x5F536B6BDB3EE14E
		rbx ^= rax;             //xor rbx, rax
		return rbx;
	}

	uintptr_t get_client_info_base() {
		uintptr_t imageBase = sdk::module_base;
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rax = driver::read<uintptr_t>(sdk::client_info + 0xae838);
		if (!rax)
			return rax;
		rbx = sdk::peb;             //mov byte ptr [rsp+0x50], 0xE0
		rcx = rbx;              //mov rcx, rbx
		rcx = _rotr64(rcx, 0xE);                //ror rcx, 0x0E
		rcx &= 0xF;
		auto clientSwitch = rcx;
		switch (rcx) {
		case 0:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r14 = imageBase + 0x797A69C3;              //lea r14, [0x00000000774BB83A]
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x0000000005058F26]
			rcx = 0xA4A4BECB119DEB05;               //mov rcx, 0xA4A4BECB119DEB05
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase + 0x68A;           //lea rcx, [0xFFFFFFFFFDD15211]
			rax += rbx;             //add rax, rbx
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rcx = driver::read<uintptr_t>(rcx + 0xf);               //mov rcx, [rcx+0x0F]
			uintptr_t RSP_0xFFFFFFFFFFFFFF98;
			RSP_0xFFFFFFFFFFFFFF98 = 0x16F104B1D7F50293;            //mov rcx, 0x16F104B1D7F50293 : RBP+0xFFFFFFFFFFFFFF98
			rcx *= RSP_0xFFFFFFFFFFFFFF98;          //imul rcx, [rbp-0x68]
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x27;           //shr rcx, 0x27
			rax ^= rcx;             //xor rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx ^= r14;             //xor rdx, r14
			rcx = 0x66DD98C660270D3C;               //mov rcx, 0x66DD98C660270D3C
			rax += rcx;             //add rax, rcx
			rdx -= rbx;             //sub rdx, rbx
			rax += rdx;             //add rax, rdx
			return rax;
		}
		case 1:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x0000000005058B0A]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x5;            //shr rcx, 0x05
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xA;            //shr rcx, 0x0A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			uintptr_t RSP_0xFFFFFFFFFFFFFF98;
			RSP_0xFFFFFFFFFFFFFF98 = 0x405886FE6E877463;            //mov rcx, 0x405886FE6E877463 : RBP+0xFFFFFFFFFFFFFF98
			rax *= RSP_0xFFFFFFFFFFFFFF98;          //imul rax, [rbp-0x68]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD14601]
			rcx += 0x5CA4;          //add rcx, 0x5CA4
			rcx += rbx;             //add rcx, rbx
			rcx ^= rax;             //xor rcx, rax
			rax = rcx;              //mov rax, rcx
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x8E5E1F38BA4BE70C;               //mov rcx, 0x8E5E1F38BA4BE70C
			rax += rcx;             //add rax, rcx
			rcx = 0xDFB9BA6CA5351E7D;               //mov rcx, 0xDFB9BA6CA5351E7D
			rax ^= rcx;             //xor rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 2:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x0000000005058644]
			r14 = imageBase + 0x50D6DEA7;              //lea r14, [0x000000004EA823A6]
			r15 = imageBase + 0x3B4D73A2;              //lea r15, [0x00000000391EB895]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rdx = rax;              //mov rdx, rax
			rdx >>= 0x30;           //shr rdx, 0x30
			rdx ^= rax;             //xor rdx, rax
			rcx = 0xF911D1A160D37B63;               //mov rcx, 0xF911D1A160D37B63
			rax = rbx;              //mov rax, rbx
			rax ^= r14;             //xor rax, r14
			rax += rdx;             //add rax, rdx
			rax *= rcx;             //imul rax, rcx
			rax += rbx;             //add rax, rbx
			uintptr_t RSP_0x60;
			RSP_0x60 = 0x3B716B0B8980E2B5;          //mov rcx, 0x3B716B0B8980E2B5 : RSP+0x60
			rax ^= RSP_0x60;                //xor rax, [rsp+0x60]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x6EC3A7C8F9867BB9;               //mov rcx, 0x6EC3A7C8F9867BB9
			rax ^= r15;             //xor rax, r15
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 3:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x000000000505824D]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1F;           //shr rcx, 0x1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3E;           //shr rcx, 0x3E
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x69EFA09A86007C6;                //mov rcx, 0x69EFA09A86007C6
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x4AB724D4F1EE21EF;               //mov rcx, 0x4AB724D4F1EE21EF
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD13D5B]
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rcx ^= rbx;             //xor rcx, rbx
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = imageBase + 0xB47E;          //lea rcx, [0xFFFFFFFFFDD1F339]
			rax -= rbx;             //sub rax, rbx
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 4:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x0000000005057E55]
			rcx = 0x3C84E6AF3448F5F9;               //mov rcx, 0x3C84E6AF3448F5F9
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x1C8C1F44C9B4F0C3;               //mov rcx, 0x1C8C1F44C9B4F0C3
			rax *= rcx;             //imul rax, rcx
			rcx = 0xFE39BA5423C48FFD;               //mov rcx, 0xFE39BA5423C48FFD
			rax += rcx;             //add rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD13BC0]
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD13AB9]
			rcx += 0xEA37;          //add rcx, 0xEA37
			rcx += rbx;             //add rcx, rbx
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 5:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x00000000050579D3]
			rax ^= rbx;             //xor rax, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xCA2CE3EE2F86830;                //mov rcx, 0xCA2CE3EE2F86830
			rax -= rcx;             //sub rax, rcx
			rcx = 0x6099DCEAD53250F5;               //mov rcx, 0x6099DCEAD53250F5
			rax += rcx;             //add rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD13798]
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xB1EA08E44E059D8D;               //mov rcx, 0xB1EA08E44E059D8D
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rax += rbx;             //add rax, rbx
			return rax;
		}
		case 6:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x00000000050575D7]
			r15 = imageBase + 0x290E968F;              //lea r15, [0x0000000026DFCB26]
			rdx = rbx;              //mov rdx, rbx
			rcx = r15;              //mov rcx, r15
			rcx = ~rcx;             //not rcx
			rdx = ~rdx;             //not rdx
			rdx *= rcx;             //imul rdx, rcx
			rcx = 0x152F2381DF7E149A;               //mov rcx, 0x152F2381DF7E149A
			rax ^= rdx;             //xor rax, rdx
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xFFFFFFFFFFFFB121;               //mov rcx, 0xFFFFFFFFFFFFB121
			rcx -= rbx;             //sub rcx, rbx
			rcx -= imageBase;          //sub rcx, [rbp-0x68] -- didn't find trace -> use base
			rax += rcx;             //add rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD133AB]
			rax -= rcx;             //sub rax, rcx
			rcx = 0xB4A2C27541D08F65;               //mov rcx, 0xB4A2C27541D08F65
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0xFFFFFFFFFFFFCA46;               //mov rcx, 0xFFFFFFFFFFFFCA46
			rcx -= rbx;             //sub rcx, rbx
			rcx -= imageBase;          //sub rcx, [rbp-0x68] -- didn't find trace -> use base
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 7:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			rdx = imageBase + 0xA09E;          //lea rdx, [0xFFFFFFFFFDD1CFDE]
			r15 = imageBase + 0x564D;          //lea r15, [0xFFFFFFFFFDD18581]
			r11 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r11, [0x0000000005057017]
			rcx = 0x47997E35DAC45EB5;               //mov rcx, 0x47997E35DAC45EB5
			rax *= rcx;             //imul rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx ^= rdx;             //xor rcx, rdx
			rdx = rbx;              //mov rdx, rbx
			rdx -= rcx;             //sub rdx, rcx
			r8 = 0;                 //and r8, 0xFFFFFFFFC0000000
			rax += rdx;             //add rax, rdx
			r8 = _rotl64(r8, 0x10);                 //rol r8, 0x10
			r8 ^= r11;              //xor r8, r11
			r8 =  (_byteswap_uint64)(r8);           //bswap r8
			rcx = 0x45C07406F46D763F;               //mov rcx, 0x45C07406F46D763F
			rax *= driver::read<uintptr_t>(r8 + 0xf);               //imul rax, [r8+0x0F]
			rax *= rcx;             //imul rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x13;           //shr rcx, 0x13
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x26;           //shr rcx, 0x26
			rax ^= rcx;             //xor rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rcx *= r15;             //imul rcx, r15
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 8:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x0000000005056C2A]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x3DAB4769DC9F44A;                //mov rcx, 0x3DAB4769DC9F44A
			rax += rcx;             //add rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD12A05]
			rax -= rcx;             //sub rax, rcx
			rcx = 0x41695AD10519D44F;               //mov rcx, 0x41695AD10519D44F
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rax += 0x6DA4;          //add rax, 0x6DA4
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 9:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x00000000050567D8]
			rax -= rbx;             //sub rax, rbx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD12483]
			rcx = rcx * 0xFFFFFFFFFFFFFFFE;                 //imul rcx, rcx, 0xFFFFFFFFFFFFFFFE
			rax += rcx;             //add rax, rcx
			rcx = 0x4EC952A8B2B2EEF;                //mov rcx, 0x4EC952A8B2B2EEF
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x339FA127D1D327AB;               //mov rcx, 0x339FA127D1D327AB
			rax *= rcx;             //imul rax, rcx
			rcx = 0xE383E7558329AD;                 //mov rcx, 0xE383E7558329AD
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x30;           //shr rcx, 0x30
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 10:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r14 = imageBase + 0x5889;          //lea r14, [0xFFFFFFFFFDD17BAC]
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x00000000050563F2]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD11EB8]
			rax += rcx;             //add rax, rcx
			rcx = r14;              //mov rcx, r14
			rcx = ~rcx;             //not rcx
			rcx += rbx;             //add rcx, rbx
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x9;            //shr rcx, 0x09
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x12;           //shr rcx, 0x12
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x24;           //shr rcx, 0x24
			rcx ^= rbx;             //xor rcx, rbx
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD12051]
			rax -= rcx;             //sub rax, rcx
			rcx = 0x2222FD5DF0AF2232;               //mov rcx, 0x2222FD5DF0AF2232
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0xB3CB6307C06C4A55;               //mov rcx, 0xB3CB6307C06C4A55
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 11:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x0000000005055FAD]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0x5C9F4BB8FD3235B6;               //mov rcx, 0x5C9F4BB8FD3235B6
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD11C85]
			rax += rcx;             //add rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rax -= rbx;             //sub rax, rbx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD11A52]
			rax -= rcx;             //sub rax, rcx
			rcx = 0xAEA6EFD7CC2EF23D;               //mov rcx, 0xAEA6EFD7CC2EF23D
			rax *= rcx;             //imul rax, rcx
			rcx = 0x55964065A5BA1B47;               //mov rcx, 0x55964065A5BA1B47
			rax -= rcx;             //sub rax, rcx
			rcx = 0xCDB070FEBAEDD3C1;               //mov rcx, 0xCDB070FEBAEDD3C1
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 12:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r11 = imageBase + 0x462D;          //lea r11, [0xFFFFFFFFFDD16038]
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x0000000005055ADA]
			rax ^= rbx;             //xor rax, rbx
			rcx = 0xD6D23102A53A019;                //mov rcx, 0xD6D23102A53A019
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xD2D9B2F000BCFEA3;               //mov rcx, 0xD2D9B2F000BCFEA3
			rax *= rcx;             //imul rax, rcx
			uintptr_t RSP_0x58;
			RSP_0x58 = 0xC298E4DA5C022161;          //mov rcx, 0xC298E4DA5C022161 : RSP+0x58
			rax ^= RSP_0x58;                //xor rax, [rsp+0x58]
			rcx = rbx;              //mov rcx, rbx
			rcx ^= r11;             //xor rcx, r11
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x7;            //shr rcx, 0x07
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 13:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r9 = driver::read<uintptr_t>(imageBase + 0x734412D);               //mov r9, [0x00000000050555D0]
			rcx = 0x60AD503CFEBA27DB;               //mov rcx, 0x60AD503CFEBA27DB
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x15;           //shr rcx, 0x15
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2A;           //shr rcx, 0x2A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xD8B754EF98F3AB20;               //mov rcx, 0xD8B754EF98F3AB20
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD11220]
			rax -= rcx;             //sub rax, rcx
			rax += 0xFFFFFFFFFFFFB3E8;              //add rax, 0xFFFFFFFFFFFFB3E8
			rax += rbx;             //add rax, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1F;           //shr rcx, 0x1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3E;           //shr rcx, 0x3E
			rax ^= rcx;             //xor rax, rcx
			rax -= rbx;             //sub rax, rbx
			rcx = 0x3E4D3C6B121F1C79;               //mov rcx, 0x3E4D3C6B121F1C79
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 14:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x00000000050550DE]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rcx = driver::read<uintptr_t>(rcx + 0xf);               //mov rcx, [rcx+0x0F]
			uintptr_t RSP_0x60;
			RSP_0x60 = 0x3558F8C0B811C83D;          //mov rcx, 0x3558F8C0B811C83D : RSP+0x60
			rcx *= RSP_0x60;                //imul rcx, [rsp+0x60]
			rax *= rcx;             //imul rax, rcx
			rcx = 0x497604B6D0A507B9;               //mov rcx, 0x497604B6D0A507B9
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rcx = imageBase + 0x1267;          //lea rcx, [0xFFFFFFFFFDD12079]
			rcx = ~rcx;             //not rcx
			rdx *= rcx;             //imul rdx, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rdx ^= rcx;             //xor rdx, rcx
			rdx ^= rbx;             //xor rdx, rbx
			rax ^= rdx;             //xor rax, rdx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD10BB0]
			rax += rcx;             //add rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD10B0B]
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 15:
		{
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			//failed to trace. Register value: rbx = 000000000014F280. base: 00007FF667200000 It's possibly wrong
			r10 = driver::read<uintptr_t>(imageBase + 0x734412D);              //mov r10, [0x0000000005054C1C]
			r15 = imageBase + 0x33288AD3;              //lea r15, [0x0000000030F995AF]
			rcx = rbx;              //mov rcx, rbx
			rcx -= imageBase;          //sub rcx, [rbp-0x68] -- didn't find trace -> use base
			rcx -= 0x578C8555;              //sub rcx, 0x578C8555
			rax ^= rcx;             //xor rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rcx = r15;              //mov rcx, r15
			rcx = ~rcx;             //not rcx
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			uintptr_t RSP_0xFFFFFFFFFFFFFF90;
			RSP_0xFFFFFFFFFFFFFF90 = 0x67F3D4815A3B7B8F;            //mov rcx, 0x67F3D4815A3B7B8F : RBP+0xFFFFFFFFFFFFFF90
			rax *= RSP_0xFFFFFFFFFFFFFF90;          //imul rax, [rbp-0x70]
			uintptr_t RSP_0xFFFFFFFFFFFFFFC8;
			RSP_0xFFFFFFFFFFFFFFC8 = 0xF76FA8C6BB7DA728;            //mov rcx, 0xF76FA8C6BB7DA728 : RBP+0xFFFFFFFFFFFFFFC8
			rax ^= RSP_0xFFFFFFFFFFFFFFC8;          //xor rax, [rbp-0x38]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x2E5B407AAFAE2F19;               //mov rcx, 0x2E5B407AAFAE2F19
			rax ^= rcx;             //xor rax, rcx
			rax += rbx;             //add rax, rbx
			return rax;
		}
		}
	}

	uint64_t get_bone() {
		uintptr_t imageBase = sdk::module_base;

		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rdx = driver::read<uintptr_t>(imageBase + 0x1BC4A488);
		if (!rdx)
			return rdx;
		r11 = sdk::peb;              //mov r11, gs:[rax]
		rax = r11;              //mov rax, r11
		rax <<= 0x29;           //shl rax, 0x29
		rax = (_byteswap_uint64)(rax);                 //bswap rax
		rax &= 0xF;
		auto clientSwitch = rax;
		switch (rax) {
		case 0:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CAB454]
			r12 = imageBase + 0x5C63FB4E;              //lea r12, [0x0000000059FA6D5B]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD966EDD]
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = rdx;              //mov rax, rdx
			rcx = r11;              //mov rcx, r11
			rax >>= 0x20;           //shr rax, 0x20
			rcx *= r12;             //imul rcx, r12
			rcx ^= rax;             //xor rcx, rax
			rdx ^= rcx;             //xor rdx, rcx
			rax = 0x234CCE505D2423F6;               //mov rax, 0x234CCE505D2423F6
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = 0x4534003F392980BD;               //mov rax, 0x4534003F392980BD
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 1:
		{
			r12 = imageBase + 0x2A4E;          //lea r12, [0xFFFFFFFFFD9697F1]
			rcx = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov rcx, [0x0000000004CAAF8F]
			rax = r12;              //mov rax, r12
			rax = ~rax;             //not rax
			rax ^= r11;             //xor rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rcx;             //xor rax, rcx
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD966C0E]
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0x7E3C7453675FB0CF;               //mov rax, 0x7E3C7453675FB0CF
			rdx *= rax;             //imul rdx, rax
			rax = 0x2776C14547FC35E3;               //mov rax, 0x2776C14547FC35E3
			rdx -= rax;             //sub rdx, rax
			rax = 0x397A3990FD34ACAE;               //mov rax, 0x397A3990FD34ACAE
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 2:
		{
			//failed to translate: pop rdx
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CAAB5A]
			r15 = imageBase + 0x40A7;          //lea r15, [0xFFFFFFFFFD96A9BA]
			rax = imageBase + 0x6866C3C6;              //lea rax, [0x0000000065FD2985]
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0xF53AD4D0A53C39D7;               //mov rax, 0xF53AD4D0A53C39D7
			rdx *= rax;             //imul rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax = rdx;              //mov rax, rdx
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax >>= 0x22;           //shr rax, 0x22
			rcx ^= r10;             //xor rcx, r10
			rdx ^= rax;             //xor rdx, rax
			rcx = (_byteswap_uint64)(rcx);                 //bswap rcx
			rdx *= driver::read<uintptr_t>(rcx + 0x13);             //imul rdx, [rcx+0x13]
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax *= r15;             //imul rax, r15
			rdx += rax;             //add rdx, rax
			rax = 0x9A516E55A768F953;               //mov rax, 0x9A516E55A768F953
			rdx *= rax;             //imul rdx, rax
			rax = 0xF90610110E52D049;               //mov rax, 0xF90610110E52D049
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD96683A]
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 3:
		{
			r12 = imageBase + 0x7C194E42;              //lea r12, [0x0000000079AFB302]
			r13 = imageBase + 0xF303;          //lea r13, [0xFFFFFFFFFD9757B2]
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CAA67E]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rax = r11;              //mov rax, r11
			rax -= imageBase;          //sub rax, [rsp+0x78] -- didn't find trace -> use base
			rax += 0xFFFFFFFF940B8C47;              //add rax, 0xFFFFFFFF940B8C47
			rdx += rax;             //add rdx, rax
			rcx = r13;              //mov rcx, r13
			rcx = ~rcx;             //not rcx
			rcx -= r11;             //sub rcx, r11
			rdx += rcx;             //add rdx, rcx
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9662BF]
			rax += 0x60FBF23D;              //add rax, 0x60FBF23D
			rax += r11;             //add rax, r11
			rdx ^= rax;             //xor rdx, rax
			uintptr_t RSP_0x60;
			RSP_0x60 = 0x9227C57B47039B3B;          //mov rax, 0x9227C57B47039B3B : RSP+0x60
			rdx *= RSP_0x60;                //imul rdx, [rsp+0x60]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD966218]
			rax += 0x113EFE7D;              //add rax, 0x113EFE7D
			rax += r11;             //add rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = r11;              //mov rax, r11
			rax *= r12;             //imul rax, r12
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 4:
		{
			r12 = imageBase + 0x7268;          //lea r12, [0xFFFFFFFFFD96D18F]
			r9 = driver::read<uintptr_t>(imageBase + 0x7344234);               //mov r9, [0x0000000004CAA0CE]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x16;           //shr rax, 0x16
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2C;           //shr rax, 0x2C
			rdx ^= rax;             //xor rdx, rax
			rdx += r11;             //add rdx, r11
			uintptr_t RSP_0x70;
			RSP_0x70 = 0xD87F1A3659490771;          //mov rax, 0xD87F1A3659490771 : RSP+0x70
			rdx *= RSP_0x70;                //imul rdx, [rsp+0x70]
			rax = r12;              //mov rax, r12
			rax ^= r11;             //xor rax, r11
			rdx -= rax;             //sub rdx, rax
			rdx -= r11;             //sub rdx, r11
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD965A2F]
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xA;            //shr rax, 0x0A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 5:
		{
			r14 = imageBase + 0x20DC0BB3;              //lea r14, [0x000000001E72655D]
			r9 = driver::read<uintptr_t>(imageBase + 0x7344234);               //mov r9, [0x0000000004CA9BC5]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = 0xA0D9F863D4FE281B;               //mov rax, 0xA0D9F863D4FE281B
			rdx *= rax;             //imul rdx, rax
			rax = 0x34E31FEFF6800654;               //mov rax, 0x34E31FEFF6800654
			rdx -= rax;             //sub rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9658D3]
			rax += 0x481F29C0;              //add rax, 0x481F29C0
			rax += rdx;             //add rax, rdx
			rdx = rax + r11 * 2;            //lea rdx, [rax+r11*2]
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r14;             //xor rdx, r14
			return rdx;
		}
		case 6:
		{
			r12 = imageBase + 0x3B397DDC;              //lea r12, [0x0000000038CFD3F2]
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA97D4]
			rax = 0x6B9DC2C9092A8F9;                //mov rax, 0x6B9DC2C9092A8F9
			rdx -= rax;             //sub rdx, rax
			rax = 0x5256F55F0CED8619;               //mov rax, 0x5256F55F0CED8619
			rdx *= rax;             //imul rdx, rax
			rdx ^= imageBase;          //xor rdx, [rsp+0x78] -- didn't find trace -> use base
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD965417]
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2;            //shr rax, 0x02
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rcx = r12;              //mov rcx, r12
			rcx = ~rcx;             //not rcx
			rcx *= r11;             //imul rcx, r11
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rdx += rcx;             //add rdx, rcx
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 7:
		{
			r12 = imageBase + 0x8C0E;          //lea r12, [0xFFFFFFFFFD96DC92]
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA9255]
			rdx ^= r11;             //xor rdx, r11
			rax = 0x94FE0182791251BB;               //mov rax, 0x94FE0182791251BB
			rdx *= rax;             //imul rdx, rax
			rax = 0x53D659ED7144ED2B;               //mov rax, 0x53D659ED7144ED2B
			rdx *= rax;             //imul rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rax = r11 + r12 * 1;            //lea rax, [r11+r12*1]
			rcx =  (_byteswap_uint64)(rcx);                 //bswap rcx
			rdx ^= rax;             //xor rdx, rax
			rdx *= driver::read<uintptr_t>(rcx + 0x13);             //imul rdx, [rcx+0x13]
			rax = imageBase + 0x1574;          //lea rax, [0xFFFFFFFFFD966115]
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0x77202B5AF65F5B03;               //mov rax, 0x77202B5AF65F5B03
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 8:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA8D7F]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9648E4]
			rdx += rax;             //add rdx, rax
			rax = 0x1A6450AE4EA10F5;                //mov rax, 0x1A6450AE4EA10F5
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9648CC]
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x15;           //shr rax, 0x15
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2A;           //shr rax, 0x2A
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD96490A]
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase + 0x6B499480;              //lea rax, [0x0000000068DFDD16]
			rax *= r11;             //imul rax, r11
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 9:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x7344234);               //mov r9, [0x0000000004CA88DD]
			rax = 0xBEBB5B8975FFBBA3;               //mov rax, 0xBEBB5B8975FFBBA3
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rdx ^= rax;             //xor rdx, rax
			rax = 0x19763EF0D6D2149F;               //mov rax, 0x19763EF0D6D2149F
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = 0x80807EBB5195B7DB;               //mov rax, 0x80807EBB5195B7DB
			rdx *= rax;             //imul rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rdx ^= r11;             //xor rdx, r11
			rax = imageBase + 0xBC10;          //lea rax, [0xFFFFFFFFFD96FF98]
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 10:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA8479]
			r15 = imageBase + 0x5899D6F6;              //lea r15, [0x0000000056301923]
			rax = 0xA3EE00FB94345282;               //mov rax, 0xA3EE00FB94345282
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x13;           //shr rax, 0x13
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			rdx -= r11;             //sub rdx, r11
			rax = 0xBABA0389369536A7;               //mov rax, 0xBABA0389369536A7
			rdx *= rax;             //imul rdx, rax
			rax = 0x1C33FA7670BAB76D;               //mov rax, 0x1C33FA7670BAB76D
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 11:
		{
			r15 = imageBase + 0x735F;          //lea r15, [0xFFFFFFFFFD96B050]
			rcx = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov rcx, [0x0000000004CA7EE6]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x16;           //shr rax, 0x16
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2C;           //shr rax, 0x2C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x17;           //shr rax, 0x17
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2E;           //shr rax, 0x2E
			rdx ^= rax;             //xor rdx, rax
			rax = 0x253ECA2C20367777;               //mov rax, 0x253ECA2C20367777
			rdx += rax;             //add rdx, rax
			rax = 0x768BAD618CDBD711;               //mov rax, 0x768BAD618CDBD711
			rdx *= rax;             //imul rdx, rax
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1;            //shr rax, 0x01
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2;            //shr rax, 0x02
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rdx -= r11;             //sub rdx, r11
			rdx -= imageBase;          //sub rdx, [rsp+0x78] -- didn't find trace -> use base
			rdx -= 0x10FBB2DC;              //sub rdx, 0x10FBB2DC
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rcx;             //xor rax, rcx
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			return rdx;
		}
		case 12:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA79A6]
			r13 = imageBase + 0x8687;          //lea r13, [0xFFFFFFFFFD96BDE6]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase + 0x693CAA5F;              //lea rax, [0x0000000066D2DE70]
			rax -= r11;             //sub rax, r11
			rdx += rax;             //add rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD963650]
			rdx -= rax;             //sub rdx, rax
			rax = r11 + r13 * 1;            //lea rax, [r11+r13*1]
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2;            //shr rax, 0x02
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9632CD]
			rdx ^= rax;             //xor rdx, rax
			rax = 0xC9BA9B7F1A3D8457;               //mov rax, 0xC9BA9B7F1A3D8457
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 13:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA7303]
			r12 = imageBase + 0x342F3E08;              //lea r12, [0x0000000031C56EC4]
			r13 = imageBase + 0x638F;          //lea r13, [0xFFFFFFFFFD96943F]
			rdx ^= r11;             //xor rdx, r11
			rax = rdx;              //mov rax, rdx
			rax >>= 0x21;           //shr rax, 0x21
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rcx = r13;              //mov rcx, r13
			rcx = ~rcx;             //not rcx
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rdx += rax;             //add rdx, rax
			rdx += rcx;             //add rdx, rcx
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax *= r12;             //imul rax, r12
			rdx ^= rax;             //xor rdx, rax
			rdx += r11;             //add rdx, r11
			rax = 0x1320F6A473E82938;               //mov rax, 0x1320F6A473E82938
			rdx ^= rax;             //xor rdx, rax
			rax = 0xBC7E761DD877CBB7;               //mov rax, 0xBC7E761DD877CBB7
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 14:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7344234);              //mov r10, [0x0000000004CA6D50]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rax = 0x4B117A2BD7B4272D;               //mov rax, 0x4B117A2BD7B4272D
			rdx -= rax;             //sub rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rcx = imageBase + 0xD92F;          //lea rcx, [0xFFFFFFFFFD970227]
			rax = rdx;              //mov rax, rdx
			rcx = ~rcx;             //not rcx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = 0xFEB1862AE3FCD98E;               //mov rax, 0xFEB1862AE3FCD98E
			rdx ^= rax;             //xor rdx, rax
			rax = 0xCA7468560838EC09;               //mov rax, 0xCA7468560838EC09
			rdx *= rax;             //imul rdx, rax
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rcx *= rax;             //imul rcx, rax
			rdx += rcx;             //add rdx, rcx
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2;            //shr rax, 0x02
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 15:
		{
			//failed to translate: pop rdx
			r9 = driver::read<uintptr_t>(imageBase + 0x7344234);               //mov r9, [0x0000000004CA67E3]
			r15 = imageBase + 0x11732B42;              //lea r15, [0x000000000F0950DE]
			rdx ^= r11;             //xor rdx, r11
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax ^= r15;             //xor rax, r15
			rax += imageBase;          //add rax, [rsp+0x78] -- didn't find trace -> use base
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xD;            //shr rax, 0x0D
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax =  (_byteswap_uint64)(rax);                 //bswap rax
			rax = driver::read<uintptr_t>(rax + 0x13);              //mov rax, [rax+0x13]
			rdx *= rax;             //imul rdx, rax
			rax = 0xEBB3D4EB5F7AFD81;               //mov rax, 0xEBB3D4EB5F7AFD81
			rdx *= rax;             //imul rdx, rax
			rax = 0x2A8275F021D1CFB7;               //mov rax, 0x2A8275F021D1CFB7
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		}
	}    
	
	//extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t { uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;         RBX = index;      RCX = RBX * 0x13C8;      RAX = 0x38AE5B395E3D4CAF;      R11 = imageBase;      RAX = _umul128(RAX, RCX, &RDX);      RAX = RCX;      R10 = 0x84B6DEFBC166BE53;      RAX -= RDX;      RAX >>= 0x1;      RAX += RDX;      RAX >>= 0xC;      RAX = RAX * 0x1A33;      RCX -= RAX;      RAX = 0xACA5D1C2D702414B;      R8 = RCX * 0x1A33;      RAX = _umul128(RAX, R8, &RDX);      RDX >>= 0xD;      RAX = RDX * 0x2F73;      R8 -= RAX;      RAX = 0xBC0D38EE00BC0D39;      RAX = _umul128(RAX, R8, &RDX);      RAX = 0xD79435E50D79435F;      RDX >>= 0x9;      RCX = RDX * 0x2B9;      RAX = _umul128(RAX, R8, &RDX);      RDX >>= 0x4;      RCX += RDX;      RAX = RCX * 0x26;      RCX = R8 + R8 * 4;      RCX <<= 0x3;      RCX -= RAX;      RAX = driver::read<uint16_t>(RCX + R11 + 0x73AFF80);      R8 = RAX * 0x13C8;      RAX = R10;      RAX = _umul128(RAX, R8, &RDX);      RAX = R10;      RDX >>= 0xC;      RCX = RDX * 0x1EDD;      R8 -= RCX;      R9 = R8 * 0x26C2;      RAX = _umul128(RAX, R9, &RDX);      RDX >>= 0xC;      RAX = RDX * 0x1EDD;      R9 -= RAX;      RAX = 0xCCCCCCCCCCCCCCCD;      RAX = _umul128(RAX, R9, &RDX);      RAX = 0x6279F0FF6C491681;      RDX >>= 0x3;      RCX = RDX + RDX * 4;      RAX = _umul128(RAX, R9, &RDX);      RDX >>= 0x9;      RAX = RDX + RCX * 2;      RCX = RAX * 0xA66;      RAX = R9 * 0xA68;      RAX -= RCX;      R15 = driver::read<uint16_t>(RAX + R11 + 0x73B6700);      return R15;  return RDX; }

	uint32_t get_bone_index(uint32_t index) {
		uintptr_t imageBase = sdk::module_base;
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = index;
		rcx = rbx * 0x13C8;
		rax = 0x59C7861968F98ABF;               //mov rax, 0x59C7861968F98ABF
		r11 = imageBase;           //lea r11, [0xFFFFFFFFFDD281FD]
		rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
		rax = rcx;              //mov rax, rcx
		r10 = 0x4B40C7E412F5D25D;               //mov r10, 0x4B40C7E412F5D25D
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0xC;            //shr rax, 0x0C
		rax = rax * 0x17B1;             //imul rax, rax, 0x17B1
		rcx -= rax;             //sub rcx, rax
		rax = 0x7A3D746C2271B8AB;               //mov rax, 0x7A3D746C2271B8AB
		r8 = rcx * 0x17B1;              //imul r8, rcx, 0x17B1
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r8;               //mov rax, r8
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0xD;            //shr rax, 0x0D
		rax = rax * 0x2B51;             //imul rax, rax, 0x2B51
		r8 -= rax;              //sub r8, rax
		rax = 0x9374217D63C7A889;               //mov rax, 0x9374217D63C7A889
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r8;               //mov rax, r8
		rcx = r8;               //mov rcx, r8
		rax -= rdx;             //sub rax, rdx
		r8 &= 0x7;             //and r8d, 0x07
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0xB;            //shr rax, 0x0B
		rax = rax * 0xA27;              //imul rax, rax, 0xA27
		rcx -= rax;             //sub rcx, rax
		rax = r8 + rcx * 8;             //lea rax, [r8+rcx*8]
		rax = driver::read<uint16_t>(r11 + rax * 2 + 0x7359EC0);                //movzx eax, word ptr [r11+rax*2+0x7359EC0]
		r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
		rax = r10;              //mov rax, r10
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r10;              //mov rax, r10
		rdx >>= 0xB;            //shr rdx, 0x0B
		rcx = rdx * 0x1B37;             //imul rcx, rdx, 0x1B37
		r8 -= rcx;              //sub r8, rcx
		r9 = r8 * 0x2F60;               //imul r9, r8, 0x2F60
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0xB;            //shr rdx, 0x0B
		rax = rdx * 0x1B37;             //imul rax, rdx, 0x1B37
		r9 -= rax;              //sub r9, rax
		rax = 0xE38E38E38E38E38F;               //mov rax, 0xE38E38E38E38E38F
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = 0x905A38633E06C43B;               //mov rax, 0x905A38633E06C43B
		rdx >>= 0x5;            //shr rdx, 0x05
		rcx = rdx + rdx * 8;            //lea rcx, [rdx+rdx*8]
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0x7;            //shr rdx, 0x07
		rax = rdx + rcx * 4;            //lea rax, [rdx+rcx*4]
		rcx = rax * 0x1C6;              //imul rcx, rax, 0x1C6
		rax = r9 * 0x1C8;               //imul rax, r9, 0x1C8
		rax -= rcx;             //sub rax, rcx
		rsi = driver::read<uint16_t>(rax + r11 * 1 + 0x7364130);                //movsx esi, word ptr [rax+r11*1+0x7364130]
		return rsi;
	}

	struct ref_def_key {
		int ref0;
		int ref1;
		int ref2;
	};

	uintptr_t get_ref_def() {
		ref_def_key crypt = driver::read<ref_def_key>(sdk::module_base + offsets::ref_def_ptr);
		uint64_t baseAddr = sdk::module_base;

		DWORD lower = crypt.ref0 ^ (crypt.ref2 ^ (uint64_t)(baseAddr + offsets::ref_def_ptr)) * ((crypt.ref2 ^ (uint64_t)(baseAddr + offsets::ref_def_ptr)) + 2);
		DWORD upper = crypt.ref1 ^ (crypt.ref2 ^ (uint64_t)(baseAddr + offsets::ref_def_ptr + 0x4)) * ((crypt.ref2 ^ (uint64_t)(baseAddr + offsets::ref_def_ptr + 0x4)) + 2);

		return (uint64_t)upper << 32 | lower; 
	}
}
    