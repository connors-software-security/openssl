#!/usr/bin/env perl
while (($output=shift) && ($output!~/^\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$code.=<<___;
#ifndef __KERNEL__
# include "arm_arch.h"
#endif

#if __ARM_MAX_ARCH__>=7
.arch	armv7-a
.fpu	neon

.text
.syntax	unified 	@ ARMv7-capable assembler is expected to handle this
#ifdef __thumb2__
.thumb
#else
.code   32
#endif

.extern NEWHOPE_psirev_1024
.extern NEWHOPE_psiinv_1024
.extern NEWHOPE_ninv_1024
.extern NEWHOPE_npsiinv_1024

___

$psirev="r3";
$psiinv=$psirev;

$U="q0";
$Ul="d0";
$Uh="d1";
$V="q1";
$Vl="d2";
$Vh="d3";
$qtemp="q2";
$qtempl="d4";
$qtemph="d5";
$dtemp="d4";
$S="q3";
$Sl="d6";
$Sh="d7";
$kredmask="q8";
$kredmaskd="d16";
$kredtemp="q9";
$kredtempd="d18";

$ninv="${Sl}[0]";
$npsiinv="${Sl}[1]";

sub kredd()
{ my ($c) = @_;
  $code.="	vand.s32	$kredtempd,$c,$kredmaskd\n";
  $code.="	vshr.s32	$c,$c,#12\n";
  $code.="	vsub.s32	$c,$kredtempd,$c\n";
  $code.="	vadd.s32	$c,$kredtempd,$c\n";
  $code.="	vadd.s32	$c,$kredtempd,$c\n";
}

sub kred()
{ my ($c) = @_;
  $code.="	vand.s32	$kredtemp,$c,$kredmask\n";
  $code.="	vshr.s32	$c,$c,#12\n";
  $code.="	vsub.s32	$c,$kredtemp,$c\n";
  $code.="	vadd.s32	$c,$kredtemp,$c\n";
  $code.="	vadd.s32	$c,$kredtemp,$c\n";
}

$code.=<<___;
.globl  NEWHOPE_poly_ntt_1024_asm
.hidden NEWHOPE_poly_ntt_1024_asm
.type	NEWHOPE_poly_ntt_1024_asm,%function
.align	4
NEWHOPE_poly_ntt_1024_asm:
	ldr	r3,.LOPENSSL_armcap_P
	adr	r2,.LOPENSSL_armcap_P
	add	r3,r3,r2
	ldr	r3,[r3]
	tst	r3,#ARMV7_NEON
	bne	.Lntt_neon_entry
	mov	r0,#0
	bx	lr
.size NEWHOPE_poly_ntt_1024_asm,.-NEWHOPE_poly_ntt_1024_asm

.globl  NEWHOPE_poly_intt_1024_asm
.hidden NEWHOPE_poly_intt_1024_asm
.type	NEWHOPE_poly_intt_1024_asm,%function
.align	4
NEWHOPE_poly_intt_1024_asm:
	ldr	r3,.LOPENSSL_armcap_P
	adr	r2,.LOPENSSL_armcap_P
	add	r3,r3,r2
	ldr	r3,[r3]
	tst	r3,#ARMV7_NEON
	bne	.Lintt_neon_entry
	mov	r0,#0
	bx	lr
.size NEWHOPE_poly_intt_1024_asm,.-NEWHOPE_poly_intt_1024_asm

.align 4
.LOPENSSL_armcap_P:
.word	OPENSSL_armcap_P-.
.comm	OPENSSL_rmcap_P,4,4

.type NEWHOPE_poly_ntt_1024_asm_neon,%function
NEWHOPE_poly_ntt_1024_asm_neon:
.Lntt_neon_entry:
	push	{r4,r5}
	ldr	$psirev,.LNEWHOPE_psirev_1024
	adr	r2,.LNEWHOPE_psirev_1024
	add	$psirev,$psirev,r2
	vmov.i32	$kredmask,#0xfff
	@ m = 1; k = 512
	mov	r4,512
	mov	r1,r0
	add	r2,r0,#512*4
	vld1.32	{$S},[$psirev]!
.Lntt_m1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m1
	@ m = 2; k = 256
	mov	r4,256
	mov	r1,r0
	add	r2,r0,#256*4
.Lntt_m2_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m2_i0
	mov	r4,#256
	mov	r1,r2
	add	r2,r2,#256*4
.Lntt_m2_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m2_i1
	@ m = 4; k = 128
	vld1.32	{$S},[$psirev]!
	mov	r1,r0
	add	r2,r0,#128*4
	mov	r4,#128
.Lntt_m4_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m4_i0
	mov	r4,#128
	mov	r1,r2
	add	r2,r2,#128*4
.Lntt_m4_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m4_i1
	mov	r4,#128
	mov	r1,r2
	add	r2,r2,#128*4
.Lntt_m4_i2:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m4_i2
	mov	r4,#128
	mov	r1,r2
	add	r2,r2,#128*4
.Lntt_m4_i3:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m4_i3
	@ m = 8; k = 64
	mov	r1,r0
	add	r2,r0,#64*4
	mov	r5,#2
.Lntt_m8:
	vld1.32	{$S},[$psirev]!
	mov	r4,#64
.Lntt_m8_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m8_i0
	mov	r4,#64
	mov	r1,r2
	add	r2,r2,#64*4
.Lntt_m8_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m8_i1
	mov	r4,#64
	mov	r1,r2
	add	r2,r2,#64*4
.Lntt_m8_i2:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m8_i2
	mov	r4,#64
	mov	r1,r2
	add	r2,r2,#64*4
.Lntt_m8_i3:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m8_i3
	mov	r1,r2
	add	r2,r2,#64*4
	subs	r5,r5,1
	bne	.Lntt_m8
	@ m = 16; k = 32
	mov	r1,r0
	add	r2,r0,#32*4
	mov	r5,#4
.Lntt_m16:
	vld1.32	{$S},[$psirev]!
	mov	r4,#32
.Lntt_m16_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m16_i0
	mov	r4,#32
	mov	r1,r2
	add	r2,r2,#32*4
.Lntt_m16_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m16_i1
	mov	r4,#32
	mov	r1,r2
	add	r2,r2,#32*4
.Lntt_m16_i2:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m16_i2
	mov	r4,#32
	mov	r1,r2
	add	r2,r2,#32*4
.Lntt_m16_i3:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m16_i3
	mov	r1,r2
	add	r2,r2,#32*4
	subs	r5,r5,1
	bne	.Lntt_m16
	@ m = 32; k = 16
	mov	r1,r0
	add	r2,r0,#16*4
	mov	r5,#8
.Lntt_m32:
	vld1.32	{$S},[$psirev]!
	mov	r4,#16
.Lntt_m32_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m32_i0
	mov	r4,#16
	mov	r1,r2
	add	r2,r2,#16*4
.Lntt_m32_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m32_i1
	mov	r4,#16
	mov	r1,r2
	add	r2,r2,#16*4
.Lntt_m32_i2:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m32_i2
	mov	r4,#16
	mov	r1,r2
	add	r2,r2,#16*4
.Lntt_m32_i3:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m32_i3
	mov	r1,r2
	add	r2,r2,#16*4
	subs	r5,r5,1
	bne	.Lntt_m32
	@ m = 64; k = 8
	mov	r1,r0
	add	r2,r0,#8*4
	mov	r5,#16
.Lntt_m64:
	vld1.32	{$S},[$psirev]!
	mov	r4,#8
.Lntt_m64_i0:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m64_i0
	mov	r4,#8
	mov	r1,r2
	add	r2,r2,#8*4
.Lntt_m64_i1:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m64_i1
	mov	r4,#8
	mov	r1,r2
	add	r2,r2,#8*4
.Lntt_m64_i2:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m64_i2
	mov	r4,#8
	mov	r1,r2
	add	r2,r2,#8*4
.Lntt_m64_i3:
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,4
	bne	.Lntt_m64_i3
	mov	r1,r2
	add	r2,r2,#8*4
	subs	r5,r5,1
	bne	.Lntt_m64
	@ m = 128; k = 4
	mov	r1,r0
	add	r2,r0,#4*4
	mov	r5,#32
.Lntt_m128:
	vld1.32	{$S},[$psirev]!
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	mov	r1,r2
	add	r2,r2,#4*4
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sl}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	mov	r1,r2
	add	r2,r2,#4*4
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[0]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	mov	r1,r2
	add	r2,r2,#4*4
	vld1.32	{$V},[r2]
	vld1.32	{$U},[r1]
	vmul.s32	$V,$V,${Sh}[1]
___
	&kred($V);
	&kred($V);
	&kred($U);
$code.=<<___;
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	mov	r1,r2
	add	r2,r2,#4*4
	subs	r5,r5,1
	bne	.Lntt_m128
	@ m = 256; k = 2
	@ TODO reduce the number of multiplies here
	mov	r1,r0
	mov	r5,#64
.Lntt_m256:
	vld1.32	{$S},[$psirev]!
	vld1.32	{$Ul,$Uh},[r1]
	vmul.s32	$Uh,$Uh,${Sl}[0]
___
	&kredd($Uh);
$code.=<<___;
	vadd.s32	$Vl,$Uh,$Ul
	vsub.s32	$Vh,$Ul,$Uh
	vst1.32	{$Vl,$Vh},[r1]!
	vld1.32	{$Ul,$Uh},[r1]
	vmul.s32	$Uh,$Uh,${Sl}[1]
___
	&kredd($Uh);
$code.=<<___;
	vadd.s32	$Vl,$Uh,$Ul
	vsub.s32	$Vh,$Ul,$Uh
	vst1.32	{$Vl,$Vh},[r1]!
	vld1.32	{$Ul,$Uh},[r1]
	vmul.s32	$Uh,$Uh,${Sh}[0]
___
	&kredd($Uh);
$code.=<<___;
	vadd.s32	$Vl,$Uh,$Ul
	vsub.s32	$Vh,$Ul,$Uh
	vst1.32	{$Vl,$Vh},[r1]!
	vld1.32	{$Ul,$Uh},[r1]
	vmul.s32	$Uh,$Uh,${Sh}[1]
___
	&kredd($Uh);
$code.=<<___;
	vadd.s32	$Vl,$Uh,$Ul
	vsub.s32	$Vh,$Ul,$Uh
	vst1.32	{$Vl,$Vh},[r1]!
	subs	r5,r5,1
	bne	.Lntt_m256
	@ m = 512; k = 1
	mov	r1,r0
	mov	r5,#1024
.Lntt_m512:
	vld1.32	{$S},[$psirev]!
	vld1.32	{$U,$V},[r1]
	vuzp.32	$U,$V
	vmul.s32	$V,$V,$S
___
	&kred($U);
	&kred($V);
	&kred($V);
$code.=<<___;
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vzip.s32	$V,$qtemp
	vst1.32	{$V,$qtemp},[r1]!
	subs	r5,r5,#8
	bne	.Lntt_m512
	mov	r0,#1
	pop	{r4,r5}
	bx	lr
.size NEWHOPE_poly_ntt_1024_asm_neon,.-NEWHOPE_poly_ntt_1024_asm_neon
.align 4
.LNEWHOPE_psirev_1024:
.word	NEWHOPE_psirev_1024-.

.type NEWHOPE_poly_intt_1024_asm_neon,%function
NEWHOPE_poly_intt_1024_asm_neon:
.Lintt_neon_entry:
	push	{r4,r5}
	ldr	$psiinv,.LNEWHOPE_psiinv_1024
	adr	r2,.LNEWHOPE_psiinv_1024
	add	$psiinv,$psiinv,r2
	vmov.i32	$kredmask,#0xfff
	@ m = 1024; k = 1; h = 512
	mov	r1,r0
	mov	r5,#1024
	add	$psiinv,$psiinv,#512*4
.Lintt_k1:
	vld1.32	{$S},[$psiinv]!
	vld1.32	{$U,$V},[r1]
	vuzp.32	$U,$V
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,$S
___
	&kred($qtemp);
$code.=<<___;
	vzip.32	$V,$qtemp
	vst1.32	{$V,$qtemp},[r1]!
	subs	r5,#8
	bne	.Lintt_k1
	@ m = 512; k = 2; h = 256
	mov	r1,r0
	mov	r5,#1024
	sub	$psiinv,$psiinv,#(512+256)*4
.Lintt_k2:
	vld2.32	{${Sl}[],${Sh}[]},[$psiinv]!
	vld1.32	{$U,$V},[r1]
	vswp	$Uh,$Vl
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,$S
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vswp	$Vh,$qtempl
	vst1.32	{$V,$qtemp},[r1]!
	subs	r5,r5,#8
	bne	.Lintt_k2
	@ m = 256; k = 4; h = 128
	mov	r4,#1024
	mov	r1,r0
	sub	$psiinv,$psiinv,#(256+128)*4
.Lintt_k4:
	vld1.32	{$S},[$psiinv]!
	vld1.32	{$U,$V},[r1]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V,$qtemp},[r1]!
	vld1.32	{$U,$V},[r1]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V,$qtemp},[r1]!
	vld1.32	{$U,$V},[r1]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V,$qtemp},[r1]!
	vld1.32	{$U,$V},[r1]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V,$qtemp},[r1]!
	subs	r4,#8*4
	bne	.Lintt_k4
	@ m = 128; k = 8; h = 64
	mov	r5,#1024
	mov	r1,r0
	add	r2,r1,#8*4
	sub	$psiinv,$psiinv,#(128+64)*4
.Lintt_k8:
	vld1.32	{$S},[$psiinv]!
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	mov	r1,r2
	add	r2,r1,#8*4
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	mov	r1,r2
	add	r2,r1,#8*4
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	mov	r1,r2
	add	r2,r1,#8*4
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	mov	r1,r2
	add	r2,r1,#8*4
	subs	r5,r5,#8*8
	bne	.Lintt_k8
	@ m = 64; k = 16; h = 32
	mov	r5,#1024
	mov	r1,r0
	add	r2,r1,#(16*4)
	sub	$psiinv,$psiinv,#(64+32)*4
.Lintt_k16:
	vld1.32	{$S},[$psiinv]!
	mov	r4,#16
.Lintt_k16_i0:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k16_i0
	mov	r1,r2
	add	r2,r1,#16*4
	mov	r4,#16
.Lintt_k16_i1:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k16_i1
	mov	r1,r2
	add	r2,r1,#16*4
	mov	r4,#16
.Lintt_k16_i2:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k16_i2
	mov	r1,r2
	add	r2,r1,#16*4
	mov	r4,#16
.Lintt_k16_i3:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k16_i3
	mov	r1,r2
	add	r2,r1,#16*4
	subs	r5,r5,#16*8
	bne	.Lintt_k16
	@ m = 32; k = 32; h = 16
	mov	r5,#1024
	mov	r1,r0
	add	r2,r1,#(32*4)
	sub	$psiinv,$psiinv,#(32+16)*4
.Lintt_k32:
	vld1.32	{$S},[$psiinv]!
	mov	r4,#32
.Lintt_k32_i0:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k32_i0
	mov	r1,r2
	add	r2,r1,#32*4
	mov	r4,#32
.Lintt_k32_i1:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k32_i1
	mov	r1,r2
	add	r2,r1,#32*4
	mov	r4,#32
.Lintt_k32_i2:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k32_i2
	mov	r1,r2
	add	r2,r1,#32*4
	mov	r4,#32
.Lintt_k32_i3:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k32_i3
	mov	r1,r2
	add	r2,r1,#32*4
	subs	r5,r5,#32*8
	bne	.Lintt_k32
	@ m = 16; k = 64; h = 8
	mov	r5,#1024
	mov	r1,r0
	add	r2,r1,#(64*4)
	sub	$psiinv,$psiinv,#(16+8)*4
.Lintt_k64:
	vld1.32	{$S},[$psiinv]!
	mov	r4,#64
.Lintt_k64_i0:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k64_i0
	mov	r1,r2
	add	r2,r1,#64*4
	mov	r4,#64
.Lintt_k64_i1:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k64_i1
	mov	r1,r2
	add	r2,r1,#64*4
	mov	r4,#64
.Lintt_k64_i2:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k64_i2
	mov	r1,r2
	add	r2,r1,#64*4
	mov	r4,#64
.Lintt_k64_i3:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k64_i3
	mov	r1,r2
	add	r2,r1,#64*4
	subs	r5,r5,#64*8
	bne	.Lintt_k64
	@ m = 8; k = 128; h = 4
	mov	r1,r0
	add	r2,r1,#(128*4)
	sub	$psiinv,$psiinv,#(8+4)*4
	vld1.32	{$S},[$psiinv]!
	mov	r4,#128
.Lintt_k128_i0:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k128_i0
	mov	r1,r2
	add	r2,r1,#128*4
	mov	r4,#128
.Lintt_k128_i1:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k128_i1
	mov	r1,r2
	add	r2,r1,#128*4
	mov	r4,#128
.Lintt_k128_i2:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[0]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k128_i2
	mov	r1,r2
	add	r2,r1,#128*4
	mov	r4,#128
.Lintt_k128_i3:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sh}[1]
___
	&kred($qtemp);
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_k128_i3
	mov	r1,r2
	add	r2,r1,#128*4
	@ m = 4; k = 256; h = 2
	mov	r1,r0
	add	r2,r1,#256*4
	sub	$psiinv,$psiinv,#(4+2)*4
	vld1.32	{$Sl},[$psiinv]!
	mov	r4,#256
.Lintt_k256_i0:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[0]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,#4
	bne	.Lintt_k256_i0
	mov	r1,r2
	add	r2,r1,#256*4
	mov	r4,#256
.Lintt_k256_i1:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vsub.s32	$qtemp,$U,$V
	vadd.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,${Sl}[1]
___
	&kred($qtemp);
$code.=<<___;
	vst1.32	{$V},[r1]!
	vst1.32	{$qtemp},[r2]!
	subs	r4,#4
	bne	.Lintt_k256_i1
	@ finish k = 512
	ldr	r1,.LNEWHOPE_ninv_1024
	adr	r2,.LNEWHOPE_ninv_1024
	add	r1,r1,r2
	vld1.32	{$ninv}, [r1]
	ldr	r1,.LNEWHOPE_npsiinv_1024
	adr	r2,.LNEWHOPE_npsiinv_1024
	add	r1,r1,r2
	vld1.32	{$npsiinv}, [r1]
	mov	r1,r0
	add	r2,r1,#512*4
	mov	r4,#512
.Lintt_finish:
	vld1.32	{$U},[r1]
	vld1.32	{$V},[r2]
	vadd.s32	$qtemp,$U,$V
	vsub.s32	$V,$U,$V
	vmul.s32	$qtemp,$qtemp,$ninv
	vmul.s32	$V,$V,$npsiinv
___
	&kred($qtemp);
	&kred($V);
$code.=<<___;
	vst1.32	{$qtemp},[r1]!
	vst1.32	{$V},[r2]!
	subs	r4,r4,#4
	bne	.Lintt_finish
	pop	{r4,r5}
	bx	lr
.size NEWHOPE_poly_intt_1024_asm_neon,.-NEWHOPE_poly_ntt_1024_asm_neon
.align 4
.LNEWHOPE_psiinv_1024:
.word	NEWHOPE_psiinv_1024-.
.LNEWHOPE_ninv_1024:
.word	NEWHOPE_ninv_1024-.
.LNEWHOPE_npsiinv_1024:
.word	NEWHOPE_npsiinv_1024-.
#endif
___

$code =~ s/dump\s*([0-9]+)/&dump($1)/ge;

open SELF,$0;
while(<SELF>) {
	next if (/^#!/);
        last if (!s/^#/@/ and !/^$/);
        print;
}
close SELF;

print $code;

close STDOUT;
