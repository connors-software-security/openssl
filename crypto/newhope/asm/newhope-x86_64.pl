#!/usr/bin/env perl

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.19) + ($1>=2.22);
}

if (!$avx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	   `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.09) + ($1>=2.10);
}

if (!$avx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
	   `ml64 2>&1` =~ /Version ([0-9]+)\./) {
	$avx = ($1>=10) + ($1>=11);
}

if (!$avx && `$ENV{CC} -v 2>&1` =~ /((?:^clang|LLVM) version|.*based on LLVM) ([2-9]\.[0-9]+)/) {
	$avx = ($2>=3.0) + ($2>3.0);
}

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$do_dump = 0;

sub dump_a()
{
    if (!$do_dump) {
	return;
    }
    my ($m) = @_;
    $code.="	push	%rdi\n";
    $code.="	push	%r11\n";
    $code.="	mov	\$1,%esi\n";
    $code.="	mov	\$$m,%edx\n";
    $code.="	call	NH_dump_a\n";
    $code.="	pop	%r11\n";
    $code.="	pop	%rdi\n";
    $code.="	movdqa		.LNH_kred_mask(%rip),$kred_maskx\n";
    $code.="	movdqa		.LNH_sign_mask(%rip),$Sx[5]\n";
}

sub avx2_kred()
{ my ($c) = @_;
  $code.="	vpand	$kred_mask,$c,%ymm3\n";
  $code.="	vpsrad	\$12,$c,$c\n";
  $code.="	vpsubd	$c,%ymm3,$c\n";
  $code.="	vpaddd	$c,%ymm3,$c\n";
  $code.="	vpaddd	$c,%ymm3,$c\n";
}

sub avx2_kred2x()
{ my ($c) = @_;
  &avx2_kred($c);
  &avx2_kred($c);
  return;
  $code.="	vpand	$kred_mask,$c,%ymm3\n";
  $code.="	vpsrad	\$12,$c,%ymm5\n";
  $code.="	vpand	$kred_mask,%ymm5,%ymm5\n";
  $code.="	vpsrad	\$24,$c,$c\n";
  $code.="	vpaddd	%ymm3,$c,$c\n";
  $code.="	vpslld	\$3,%ymm3,%ymm3\n";
  $code.="	vpaddd	%ymm3,$c,$c\n";
  $code.="	vpsubd	%ymm5,$c,$c\n";
  $code.="	vpsubd	%ymm5,$c,$c\n";
  $code.="	vpsubd	%ymm5,$c,$c\n";
}

sub sse41_kred()
{ my ($c) = @_;
  $code.="      movdqa  $c,%xmm3\n";
  $code.="	pand	$kred_maskx,$c\n";
  $code.="	psrad	\$12,%xmm3\n";
  $code.="      movdqa  $c,%xmm5\n";
  $code.="      psubd	%xmm3,$c\n";
  $code.="	paddd	%xmm5,$c\n";
  $code.="	paddd	%xmm5,$c\n";
}

sub sse41_kred2x()
{ my ($c) = @_;
  &sse41_kred($c);
  &sse41_kred($c);
  return;
  $code.="	movdqa	$c,%xmm3\n";
  $code.="	movdqa	$c,%xmm5\n";
  $code.="	pand	$kred_maskx,%xmm3\n";
  $code.="	psrad	\$12,%xmm5\n";
  $code.="	pand	$kred_maskx,%xmm5\n";
  $code.="	psrad	\$24,$c\n";
  $code.="	paddd	%xmm3,$c\n";
  $code.="	pslld	\$3,%xmm3\n";
  $code.="	paddd	%xmm3,$c\n";
  $code.="	psubd	%xmm5,$c\n";
  $code.="	psubd	%xmm5,$c\n";
  $code.="	psubd	%xmm5,$c\n";
}

$poly="%rdi";
$U="%ymm0"; $Ux="%xmm0";
$V="%ymm1"; $Vx="%xmm1";
@S=("%ymm2","%ymm4","%ymm6","%ymm7","%ymm9","%ymm10","%ymm11","%ymm12","%ymm13","%ymm14");
@Sx=map(s/ymm/xmm/r, @S);
$kred_mask="%ymm8"; $kred_maskx="%xmm8";

$feat_avx2=1<<5;
$feat_sse41=1<<19;

$code.=<<___;
.extern NH_dump_a
.extern NEWHOPE_psirev_1024
.extern NEWHOPE_psiinv_1024
.extern NEWHOPE_psirev_512
.extern NEWHOPE_psiinv_512
.extern NEWHOPE_ninv_1024
.extern NEWHOPE_npsiinv_1024

.extern OPENSSL_ia32cap_P

.align 16
.LNH_kred_mask:
.long 0xfff, 0xfff, 0xfff, 0xfff
.LNH_sign_mask:
.long 1, -1, 1, -1


.globl  NEWHOPE_poly_ntt_1024_asm
.hidden NEWHOPE_poly_ntt_1024_asm
.type	NEWHOPE_poly_ntt_1024_asm,\@function,1
.align	16
NEWHOPE_poly_ntt_1024_asm:
	mov	OPENSSL_ia32cap_P+0(%rip),%r9d
        mov     OPENSSL_ia32cap_P+4(%rip),%r8d
        mov     OPENSSL_ia32cap_P+8(%rip),%r10d
___
$code.=<<___ if ($avx>=2);
	test	\$$feat_avx2,%r10d	# check AVX2
        jnz	_ntt_1024_avx2_shortcut
___
$code.=<<___;
	test	\$$feat_sse41,%r8d
	jnz	_ntt_1024_sse41_shortcut
        xor     %eax,%eax
        ret
.size NEWHOPE_poly_ntt_1024_asm,.-NEWHOPE_poly_ntt_1024_asm

.globl  NEWHOPE_poly_intt_1024_asm
.hidden NEWHOPE_poly_intt_1024_asm
.type	NEWHOPE_poly_intt_1024_asm,\@function,1
.align	16
NEWHOPE_poly_intt_1024_asm:
	mov	OPENSSL_ia32cap_P+0(%rip),%r9d
        mov     OPENSSL_ia32cap_P+4(%rip),%r8d
        mov     OPENSSL_ia32cap_P+8(%rip),%r10d
___
$code.=<<___ if ($avx>=2);
	and	\$$feat_avx2,%r10d	# check AVX2
        jnz      _intt_1024_avx2_shortcut
___
$code.=<<___;
	test	\$$feat_sse41,%r8d
	jnz	_intt_1024_sse41_shortcut
        xor     %eax,%eax
        ret
.size NEWHOPE_poly_intt_1024_asm,.-NEWHOPE_poly_intt_1024_asm
___

if ($avx >= 2) {

sub avx2_ntt_1k_simple_iter()
{
    my ($m) = @_;
    my $k = 1024/($m*2);
    if ($m <= 8) {
	foreach my $i (0 .. $m-1) {
	    $code.="	vpbroadcastd	NEWHOPE_psirev_1024+".(4*($m+$i))."(%rip),$S[$i]\n";
	}
	$code.="	xor	%r10,%r10\n";
	$code.=".Lavx2_ntt_1k_m$m:\n";
	foreach my $i (0 .. $m-1) {
	    my $j = 2*$i*$k;
	    $code.="	vmovdqu	".(4*$j)."($poly,%r10,4),$U\n";
	    $code.="	vmovdqu ".(4*($j+$k))."($poly,%r10,4),$V\n";
	    $code.="	vpmulld	$V,$S[$i],$V\n";
	    if ($m == 2 || $m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&avx2_kred($U);
		&avx2_kred2x($V);
	    } else {
		&avx2_kred($V);
	    }
	    $code.="	vpaddd	$V,$U,%ymm3\n";
	    $code.="	vpsubd	$V,$U,$U\n";
	    $code.="	vmovdqu	%ymm3,".(4*$j)."($poly,%r10,4)\n";
	    $code.="	vmovdqu $U,".(4*($j+$k))."($poly,%r10,4)\n";
	}
	$code.="	add	\$8,%r10\n";
	$code.="	cmp	\$$k,%r10\n";
	$code.="	jne	.Lavx2_ntt_1k_m$m\n";
    } else {
	$code.="	xor	%r10,%r10\n";
	$code.="	xor	%rcx,%rcx\n";
	$code.="	lea	NEWHOPE_psirev_1024+".(4*$m)."(%rip),%r11\n";
	$code.=".Lavx2_ntt_1k_m$m:\n";
	$code.="	vpbroadcastd	(%r11,%r10,4),$S[0]\n";
	foreach my $j (0 .. ($k/8)-1) {
	    $code.="	vmovdqu	".(4*($j*8))."($poly,%rcx,4),$U\n";
	    $code.="	vmovdqu	".(4*($j*8+$k))."($poly,%rcx,4),$V\n";
	    $code.="	vpmulld	$V,$S[0],$V\n";
	    if ($m == 2 || $m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&avx2_kred($U);
		&avx2_kred2x($V);
	    } else {
		&avx2_kred($V);
	    }
	    $code.="	vpaddd	$V,$U,%ymm3\n";
	    $code.="	vpsubd	$V,$U,$U\n";
	    $code.="	vmovdqu	%ymm3,".(4*($j*8))."($poly,%rcx,4)\n";
	    $code.="	vmovdqu $U,".(4*($j*8+$k))."($poly,%rcx,4)\n";
	}
	$code.="	add	\$1,%r10\n";
	$code.="	add	\$".(2*$k).",%rcx\n";
	$code.="	cmp	\$1024,%rcx\n";
	$code.="	jne	.Lavx2_ntt_1k_m$m\n";
    }
}

$code.=<<___;
.globl  NEWHOPE_poly_ntt_1024_avx2
.hidden NEWHOPE_poly_ntt_1024_avx2
.type	NEWHOPE_poly_ntt_1024_avx2,\@function,1
.align	16
NEWHOPE_poly_ntt_1024_avx2:
_ntt_1024_avx2_shortcut:
	vmovdqa		.LNH_kred_mask(%rip),$kred_maskx
	vinserti128	\$1,$kred_maskx,$kred_mask,$kred_mask
___
	&avx2_ntt_1k_simple_iter(1);
	&avx2_ntt_1k_simple_iter(2);
	&avx2_ntt_1k_simple_iter(4);
	&avx2_ntt_1k_simple_iter(8);
	&avx2_ntt_1k_simple_iter(16);
	&avx2_ntt_1k_simple_iter(32);
	&avx2_ntt_1k_simple_iter(64);
# m = 128
$code.=<<___;
	lea		NEWHOPE_psirev_1024+512(%rip),%r11
	xor		%r10,%r10
.Lavx2_ntt_1k_m128:
	vpbroadcastd	(%r11),$Sx[0]
	vpbroadcastd	4(%r11),$Sx[1]
	vinserti128	\$1,$Sx[1],$S[0],$S[0]
	vmovdqu		($poly,%r10,4),%ymm3
	vmovdqu		32($poly,%r10,4),$V
	vinserti128	\$1,$Vx,%ymm3,$U
	vperm2i128	\$0x13,%ymm3,$V,$V
	vpmulld		$V,$S[0],$V
___
	&avx2_kred($U);
	&avx2_kred2x($V);
$code.=<<___;
	vpaddd		$V,$U,%ymm3
	vpsubd		$V,$U,$U\n
	vperm2i128	\$0x02,%ymm3,$U,$V
	vperm2i128	\$0x13,%ymm3,$U,$U
	vmovdqu		$V,($poly,%r10,4)
	vmovdqu		$U,32($poly,%r10,4)
	add		\$8,%r11
	add		\$16,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_ntt_1k_m128
___
# m = 256
$code.=<<___;
	vmovdqa		.LNH_sign_mask(%rip),$Sx[5]
	vinserti128	\$1,$Sx[5],$S[5],$S[5]
	xor		%r10,%r10
.Lavx2_ntt_1k_m256:
	vpbroadcastd	(%r11),$Sx[0]
	vpbroadcastd	4(%r11),$Sx[1]
	vinserti128	\$1,$Sx[1],$S[0],$S[0]
	vmovdqu		($poly,%r10,4),$U
	vpmulld		$U,$S[0],$V
___
	&avx2_kred($V);
$code.=<<___;
	vpblendd	\$0b11001100,$V,$U,$U
	vpshufd		\$0b11011000,$U,$U
	vpsignd		$S[5],$U,$V
	vphaddd		$V,$U,$U
	vmovdqu		$U,($poly,%r10,4)
	add		\$8,%r11
	add		\$8,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_ntt_1k_m256
___
# m = 512
$code.=<<___;
	vpshufd		\$0b01000000,$S[5],$S[5]
	xor		%r10,%r10
.Lavx2_ntt_1k_m512:
	vpmovzxdq	(%r11),$S[0]
	vpslldq		\$4,$S[0],$S[0]
	vmovdqu		($poly,%r10,4),$U
	vpmulld		$U,$S[0],$V
___
	&avx2_kred($U);
	&avx2_kred2x($V);
$code.=<<___;
	vpblendd	\$0b10101010,$V,$U,$U
	vpshufd		\$0b11101110,$U,$V
	vpsignd		$S[5],$V,$S[7]
	vpshufd		\$0b01000100,$U,$U
	vpsignd		$S[5],$U,$S[6]
	vphaddd		$S[7],$S[6],$S[8]
	vmovdqu		$S[8],($poly,%r10,4)
	add		\$16,%r11
	add		\$8,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_ntt_1k_m512
        mov             \$1,%eax
	vzeroupper
        ret

.size	NEWHOPE_poly_ntt_1024_avx2,.-NEWHOPE_poly_ntt_1024_avx2
___


sub avx2_intt_1k_simple_iter()
{
    my ($k) = @_;
    my $m = 1024/$k;
    my $h = $m/2;
    if ($h <= 8) {
	foreach my $i (0 .. $h-1) {
	    $code.="	vpbroadcastd	NEWHOPE_psiinv_1024+".(4*($h+$i))."(%rip),$S[$i]\n";
	}
	$code.="	xor	%r10,%r10\n";
	$code.=".Lavx2_intt_1k_k$k:\n";
	foreach my $i (0 .. $h-1) {
	    my $j = 2*$i*$k;
	    $code.="	vmovdqu	".(4*$j)."($poly,%r10,4),$U\n";
	    $code.="	vmovdqu ".(4*($j+$k))."($poly,%r10,4),$V\n";
	    $code.="	vpaddd	$V,$U,$S[9]\n";
	    $code.="	vpsubd	$V,$U,$V\n";
	    $code.="	vpmulld	$V,$S[$i],$V\n";
	    if ($m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&avx2_kred($S[9]);
		&avx2_kred2x($V);
	    } else {
		&avx2_kred($V);
	    }
	    $code.="	vmovdqu	$S[9],".(4*$j)."($poly,%r10,4)\n";
	    $code.="	vmovdqu $V,".(4*($j+$k))."($poly,%r10,4)\n";
	}
	$code.="	add	\$8,%r10\n";
	$code.="	cmp	\$$k,%r10\n";
	$code.="	jne	.Lavx2_intt_1k_k$k\n";
    } else {
	$code.="	xor	%r10,%r10\n";
	$code.="	xor	%rcx,%rcx\n";
	$code.="	lea	NEWHOPE_psiinv_1024+".(4*$h)."(%rip),%r11\n";
	$code.=".Lavx2_intt_1k_k$k:\n";
	$code.="	vpbroadcastd	(%r11,%r10,4),$S[0]\n";
	foreach my $j (0 .. ($k/8)-1) {
	    $code.="	vmovdqu	".(4*($j*8))."($poly,%rcx,4),$U\n";
	    $code.="	vmovdqu	".(4*($j*8+$k))."($poly,%rcx,4),$V\n";
	    $code.="	vpaddd	$V,$U,$S[9]\n";
	    $code.="	vpsubd	$V,$U,$V\n";
	    $code.="	vpmulld	$V,$S[0],$V\n";
	    if ($m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&avx2_kred($S[9]);
		&avx2_kred2x($V);
	    } else {
		&avx2_kred($V);
	    }
	    $code.="	vmovdqu	$S[9],".(4*($j*8))."($poly,%rcx,4)\n";
	    $code.="	vmovdqu $V,".(4*($j*8+$k))."($poly,%rcx,4)\n";
	}
	$code.="	add	\$1,%r10\n";
	$code.="	add	\$".(2*$k).",%rcx\n";
	$code.="	cmp	\$1024,%rcx\n";
	$code.="	jne	.Lavx2_intt_1k_k$k\n";
    }
}

$code.=<<___;
.globl  NEWHOPE_poly_intt_1024_avx2
.hidden NEWHOPE_poly_intt_1024_avx2
.type	NEWHOPE_poly_intt_1024_avx2,\@function,1
.align	16
NEWHOPE_poly_intt_1024_avx2:
_intt_1024_avx2_shortcut:
	vmovdqa		.LNH_kred_mask(%rip),$kred_maskx
	vinserti128	\$1,$kred_maskx,$kred_mask,$kred_mask
	vmovdqa		.LNH_sign_mask(%rip),$Sx[5]
	vinserti128	\$1,$Sx[5],$S[5],$S[5]
___
# k = 1
$code.=<<___;
	xor		%r10,%r10
	lea		NEWHOPE_psiinv_1024+2048(%rip),%r11
.Lavx2_intt_1k_k1:
	vpmovzxdq	(%r11),$S[0]
	vpslldq		\$4,$S[0],$S[0]
	vmovdqu		($poly,%r10,4),$U
	vpsignd		$S[5],$U,$V
	vphaddd		$V,$U,$U
	vpshufd		\$0b11011000,$U,$U
	vpmulld		$U,$S[0],$V
___
	&avx2_kred($V);
$code.=<<___;
	vpblendd	\$0b10101010,$V,$U,$U
	vmovdqu		$U,($poly,%r10,4)
	add		\$16,%r11
	add		\$8,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_intt_1k_k1
___
	&dump_a(1);
# k = 2
$code.=<<___;
	xor		%r10,%r10
	lea		NEWHOPE_psiinv_1024+1024(%rip),%r11
.Lavx2_intt_1k_k2:
	vpbroadcastd	(%r11),$Sx[0]
	vpbroadcastd	4(%r11),$Sx[1]
	vinserti128	\$1,$Sx[1],$S[0],$S[0]
	vmovdqu		($poly,%r10,4),$U
	vpshufd		\$0b11011000,$U,$U
	vpsignd		$S[5],$U,$V
	vphaddd		$V,$U,$U
	vpmulld		$U,$S[0],$V
___
	&avx2_kred($U);
	&avx2_kred2x($V);
$code.=<<___;
	vpblendd	\$0b11001100,$V,$U,$U
	vmovdqu		$U,($poly,%r10,4)
	add		\$8,%r11
	add		\$8,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_intt_1k_k2
___
	&dump_a(2);
# k = 4
$code.=<<___;
	lea		NEWHOPE_psiinv_1024+512(%rip),%r11
	xor		%r10,%r10
.Lavx2_intt_1k_k4:
	vpbroadcastd	(%r11),$Sx[0]
	vpbroadcastd	4(%r11),$Sx[1]
	vinserti128	\$1,$Sx[1],$S[0],$S[0]
	vmovdqu		($poly,%r10,4),$S[3]
	vmovdqu		32($poly,%r10,4),$V
	vinserti128	\$1,$Vx,$S[3],$U
	vperm2i128	\$0x13,$S[3],$V,$V
	vpaddd		$V,$U,$S[3]
	vpsubd		$V,$U,$V\n
	vpmulld		$V,$S[0],$V
___
	&avx2_kred($V);
$code.=<<___;
	vperm2i128	\$0x13,$S[3],$V,$U
	vperm2i128	\$0x02,$S[3],$V,$V
	vmovdqu		$V,($poly,%r10,4)
	vmovdqu		$U,32($poly,%r10,4)
	add		\$8,%r11
	add		\$16,%r10
	cmp		\$1024,%r10
	jne		.Lavx2_intt_1k_k4
___
	&dump_a(4);
	&avx2_intt_1k_simple_iter(8);
	&dump_a(8);
	&avx2_intt_1k_simple_iter(16);
	&dump_a(16);
	&avx2_intt_1k_simple_iter(32);
	&dump_a(32);
	&avx2_intt_1k_simple_iter(64);
	&dump_a(64);
	&avx2_intt_1k_simple_iter(128);
	&dump_a(128);
	&avx2_intt_1k_simple_iter(256);
	&dump_a(256);
$code.=<<___;
	vpbroadcastd	NEWHOPE_ninv_1024(%rip),$S[0]
	vpbroadcastd	NEWHOPE_npsiinv_1024(%rip),$S[1]
	xor		%r10,%r10
.Lavx2_intt_1k_k512:
	vmovdqu		($poly,%r10,4),$U
	vmovdqu		2048($poly,%r10,4),$V
	vpaddd		$V,$U,%ymm3
	vpsubd		$V,$U,$V
	vpmulld		$S[1],$V,$V
	vpmulld		$S[0],%ymm3,$U
___
	&avx2_kred($U);
	&avx2_kred($V);
$code.=<<___;
	vmovdqu		$U,($poly,%r10,4)
	vmovdqu		$V,2048($poly,%r10,4)
	add		\$8,%r10
	cmp		\$512,%r10
	jne		.Lavx2_intt_1k_k512
___
	&dump_a(512);
$code.=<<___;
        mov \$1,%eax
	vzeroupper
	ret
.size	NEWHOPE_poly_intt_1024_avx2,.-NEWHOPE_poly_intt_1024_avx2
___
}

sub sse41_ntt_1k_simple_iter()
{
    my ($m) = @_;
    my $k = 1024/($m*2);
    if ($m <= 8) {
	foreach my $i (0 .. $m-1) {
	    $code.="	movd	NEWHOPE_psirev_1024+".(4*($m+$i))."(%rip),$Sx[$i]\n";
	    $code.="	pshufd	\$0,$Sx[$i],$Sx[$i]\n";
	}
	$code.="	xor	%r10,%r10\n";
	$code.=".Lsse41_ntt_1k_m$m:\n";
	foreach my $i (0 .. $m-1) {
	    my $j = 2*$i*$k;
	    $code.="	movdqu	".(4*$j)."($poly,%r10,4),$Ux\n";
	    $code.="	movdqu ".(4*($j+$k))."($poly,%r10,4),$Vx\n";
	    $code.="	pmulld	$Sx[$i],$Vx\n";
	    if ($m == 2 || $m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&sse41_kred($Ux);
		&sse41_kred2x($Vx);
	    } else {
		&sse41_kred($Vx);
	    }
	    $code.="	movdqu	$Ux,%xmm3\n";
	    $code.="	paddd	$Vx,%xmm3\n";
	    $code.="	psubd	$Vx,$Ux\n";
	    $code.="	movdqu	%xmm3,".(4*$j)."($poly,%r10,4)\n";
	    $code.="	movdqu	$Ux,".(4*($j+$k))."($poly,%r10,4)\n";
	}
	$code.="	add	\$4,%r10\n";
	$code.="	cmp	\$$k,%r10\n";
	$code.="	jne	.Lsse41_ntt_1k_m$m\n";
    } else {
	$code.="	xor	%r10,%r10\n";
	$code.="	xor	%rcx,%rcx\n";
	$code.="	lea	NEWHOPE_psirev_1024+".(4*$m)."(%rip),%r11\n";
	$code.=".Lsse41_ntt_1k_m$m:\n";
	$code.="	movd	(%r11,%r10,4),$Sx[0]\n";
	$code.="	pshufd	\$0,$Sx[0],$Sx[0]\n";
	foreach my $j (0 .. ($k/4)-1) {
	    $code.="	movdqu	".(4*($j*4))."($poly,%rcx,4),$Ux\n";
	    $code.="	movdqu	".(4*($j*4+$k))."($poly,%rcx,4),$Vx\n";
	    $code.="	pmulld	$Sx[0],$Vx\n";
	    if ($m == 2 || $m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&sse41_kred($Ux);
		&sse41_kred2x($Vx);
	    } else {
		&sse41_kred($Vx);
	    }
	    $code.="	movdqu	$Ux,%xmm3\n";
	    $code.="	paddd	$Vx,%xmm3\n";
	    $code.="	psubd	$Vx,$Ux\n";
	    $code.="	movdqu	%xmm3,".(4*($j*4))."($poly,%rcx,4)\n";
	    $code.="	movdqu	$Ux,".(4*($j*4+$k))."($poly,%rcx,4)\n";
	}
	$code.="	add	\$1,%r10\n";
	$code.="	add	\$".(2*$k).",%rcx\n";
	$code.="	cmp	\$1024,%rcx\n";
	$code.="	jne	.Lsse41_ntt_1k_m$m\n";
    }
}
$code.=<<___;
.globl  NEWHOPE_poly_ntt_1024_sse41
.hidden NEWHOPE_poly_ntt_1024_sse41
.type	NEWHOPE_poly_ntt_1024_sse41,\@function,1
.align	16
NEWHOPE_poly_ntt_1024_sse41:
_ntt_1024_sse41_shortcut:
	movdqa		.LNH_kred_mask(%rip),$kred_maskx
___
	&sse41_ntt_1k_simple_iter(1);
	&dump_a(1);
	&sse41_ntt_1k_simple_iter(2);
	&dump_a(2);
	&sse41_ntt_1k_simple_iter(4);
	&dump_a(4);
	&sse41_ntt_1k_simple_iter(8);
	&dump_a(8);
	&sse41_ntt_1k_simple_iter(16);
	&dump_a(16);
	&sse41_ntt_1k_simple_iter(32);
	&dump_a(32);
	&sse41_ntt_1k_simple_iter(64);
	&dump_a(64);
	&sse41_ntt_1k_simple_iter(128);
	&dump_a(128);
# m = 256
$code.=<<___;
	lea		NEWHOPE_psirev_1024+1024(%rip),%r11
	movdqa		.LNH_sign_mask(%rip),$Sx[5]
	xor		%r10,%r10
.Lsse41_ntt_1k_m256:
	movd		(%r11),$Sx[0]
	pshufd		\$0,$Sx[0],$Sx[0]
	movdqu		($poly,%r10,4),$Ux
	movdqa		$Ux,$Vx
	pmulld		$Sx[0],$Vx
___
	&sse41_kred($Vx);
$code.=<<___;
	pblendw		\$0b11110000,$Vx,$Ux
	pshufd		\$0b11011000,$Ux,$Ux
	movdqa		$Ux,$Vx
	psignd		$Sx[5],$Vx
	phaddd		$Vx,$Ux
	movdqu		$Ux,($poly,%r10,4)
	add		\$4,%r11
	add		\$4,%r10
	cmp		\$1024,%r10
	jne		.Lsse41_ntt_1k_m256
___
	&dump_a(256);
# m = 512
$code.=<<___;
	pshufd		\$0b01000000,$Sx[5],$Sx[5]
	xor		%r10,%r10
.Lsse41_ntt_1k_m512:
	movq		(%r11),$Sx[0]
	movdqu		($poly,%r10,4),$Ux
	pshufd		\$0b01010000,$Sx[0],$Sx[0]
	movdqa		$Ux,$Vx
	pmulld		$Sx[0],$Vx
___
	&sse41_kred($Ux);
	&sse41_kred2x($Vx);
$code.=<<___;
	pblendw		\$0b11001100,$Vx,$Ux
	pshufd		\$0b11101110,$Ux,$Vx
	psignd		$Sx[5],$Vx
	pshufd		\$0b01000100,$Ux,$Ux
	psignd		$Sx[5],$Ux
	phaddd		$Vx,$Ux
	movdqu		$Ux,($poly,%r10,4)
	add		\$8,%r11
	add		\$4,%r10
	cmp		\$1024,%r10
	jne		.Lsse41_ntt_1k_m512
___
	&dump_a(512);
$code.=<<___;
        mov             \$1,%eax
        ret

.size	NEWHOPE_poly_ntt_1024_sse41,.-NEWHOPE_poly_ntt_1024_sse41
___


sub sse41_intt_1k_simple_iter()
{
    my ($k) = @_;
    my $m = 1024/$k;
    my $h = $m/2;
    if ($h <= 8) {
	foreach my $i (0 .. $h-1) {
	    $code.="	movd	NEWHOPE_psiinv_1024+".(4*($h+$i))."(%rip),$Sx[$i]\n";
	    $code.="	pshufd	\$0,$Sx[$i],$Sx[$i]\n";
	}
	$code.="	xor	%r10,%r10\n";
	$code.=".Lsse41_intt_1k_k$k:\n";
	foreach my $i (0 .. $h-1) {
	    my $j = 2*$i*$k;
	    $code.="	movdqu	".(4*$j)."($poly,%r10,4),$Ux\n";
	    $code.="	movdqu ".(4*($j+$k))."($poly,%r10,4),$Vx\n";
	    $code.="	movdqa	$Ux,$Sx[9]\n";
	    $code.="	paddd	$Vx,$Sx[9]\n";
	    $code.="	psubd	$Vx,$Ux\n";
	    $code.="	pmulld	$Sx[$i],$Ux\n";
	    if ($m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&sse41_kred($Sx[9]);
		&sse41_kred2x($Ux);
	    } else {
		&sse41_kred($Ux);
	    }
	    $code.="	movdqu	$Sx[9],".(4*$j)."($poly,%r10,4)\n";
	    $code.="	movdqu	$Ux,".(4*($j+$k))."($poly,%r10,4)\n";
	}
	$code.="	add	\$4,%r10\n";
	$code.="	cmp	\$$k,%r10\n";
	$code.="	jne	.Lsse41_intt_1k_k$k\n";
    } else {
	$code.="	xor	%r10,%r10\n";
	$code.="	xor	%rcx,%rcx\n";
	$code.="	lea	NEWHOPE_psiinv_1024+".(4*$h)."(%rip),%r11\n";
	$code.=".Lsse41_intt_1k_k$k:\n";
	$code.="	movd	(%r11,%r10,4),$Sx[0]\n";
	$code.="	pshufd	\$0,$Sx[0],$Sx[0]\n";
	foreach my $j (0 .. ($k/4)-1) {
	    $code.="	movdqu	".(4*($j*4))."($poly,%rcx,4),$Ux\n";
	    $code.="	movdqu	".(4*($j*4+$k))."($poly,%rcx,4),$Vx\n";
	    $code.="	movdqa	$Ux,$Sx[9]\n";
	    $code.="	paddd	$Vx,$Sx[9]\n";
	    $code.="	psubd	$Vx,$Ux\n";
	    $code.="	pmulld	$Sx[0],$Ux\n";
	    if ($m == 8 || $m == 32 || $m == 128 || $m == 512) {
		&sse41_kred($Sx[9]);
		&sse41_kred2x($Ux);
	    } else {
		&sse41_kred($Ux);
	    }
	    $code.="	movdqu	$Sx[9],".(4*($j*4))."($poly,%rcx,4)\n";
	    $code.="	movdqu	$Ux,".(4*($j*4+$k))."($poly,%rcx,4)\n";
	}
	$code.="	add	\$1,%r10\n";
	$code.="	add	\$".(2*$k).",%rcx\n";
	$code.="	cmp	\$1024,%rcx\n";
	$code.="	jne	.Lsse41_intt_1k_k$k\n";
    }
}

$do_dump = 0;

$code.=<<___;
.globl  NEWHOPE_poly_intt_1024_sse41
.hidden NEWHOPE_poly_intt_1024_sse41
.type	NEWHOPE_poly_intt_1024_sse41,\@function,1
.align	16
NEWHOPE_poly_intt_1024_sse41:
_intt_1024_sse41_shortcut:
	movdqa		.LNH_kred_mask(%rip),$kred_maskx
	movdqa		.LNH_sign_mask(%rip),$Sx[5]
___
# k = 1
$code.=<<___;
	xor		%r10,%r10
	lea		NEWHOPE_psiinv_1024+2048(%rip),%r11
.Lsse41_intt_1k_k1:
	movq		(%r11),$Sx[0]
	pshufd		\$0b01010000,$Sx[0],$Sx[0]
	movdqu		($poly,%r10,4),$Ux
	movdqa		$Ux,$Vx
	psignd		$Sx[5],$Vx
	phaddd		$Vx,$Ux
	pshufd		\$0b11011000,$Ux,$Ux
	movdqa		$Ux,$Vx
	pmulld		$Sx[0],$Vx
___
	&sse41_kred($Vx);
$code.=<<___;
	pblendw		\$0b11001100,$Vx,$Ux
	movdqu		$Ux,($poly,%r10,4)
	add		\$8,%r11
	add		\$4,%r10
	cmp		\$1024,%r10
	jne		.Lsse41_intt_1k_k1
___
	&dump_a(1);
# k = 2
$code.=<<___;
	xor		%r10,%r10
	lea		NEWHOPE_psiinv_1024+1024(%rip),%r11
.Lsse41_intt_1k_k2:
	movd		(%r11),$Sx[0]
	pshufd		\$0,$Sx[0],$Sx[0]
	movdqu		($poly,%r10,4),$Ux
	pshufd		\$0b11011000,$Ux,$Ux
	movdqa		$Ux,$Vx
	psignd		$Sx[5],$Vx
	phaddd		$Vx,$Ux
	movdqa		$Ux,$Vx
	pmulld		$Sx[0],$Vx
___
	&sse41_kred($Ux);
	&sse41_kred2x($Vx);
$code.=<<___;
	pblendw		\$0b11110000,$Vx,$Ux
	movdqu		$Ux,($poly,%r10,4)
	add		\$4,%r11
	add		\$4,%r10
	cmp		\$1024,%r10
	jne		.Lsse41_intt_1k_k2
___
	&dump_a(2);
	&sse41_intt_1k_simple_iter(4);
	&dump_a(4);
	&sse41_intt_1k_simple_iter(8);
	&dump_a(8);
	&sse41_intt_1k_simple_iter(16);
	&dump_a(16);
	&sse41_intt_1k_simple_iter(32);
	&dump_a(32);
	&sse41_intt_1k_simple_iter(64);
	&dump_a(64);
	&sse41_intt_1k_simple_iter(128);
	&dump_a(128);
	&sse41_intt_1k_simple_iter(256);
	&dump_a(256);
$code.=<<___;
	movd		NEWHOPE_ninv_1024(%rip),$Sx[0]
	pshufd		\$0,$Sx[0],$Sx[0]
	movd		NEWHOPE_npsiinv_1024(%rip),$Sx[1]
	pshufd		\$0,$Sx[1],$Sx[1]
	xor		%r10,%r10
.Lsse41_intt_1k_k512:
	movdqu		($poly,%r10,4),$Ux
	movdqu		2048($poly,%r10,4),$Vx
	movdqa		$Ux,$Sx[3]
	paddd		$Vx,$Sx[3]
	psubd		$Vx,$Ux
	pmulld		$Sx[1],$Ux
	pmulld		$Sx[0],$Sx[3]
___
	&sse41_kred($Ux);
	&sse41_kred($Sx[3]);
$code.=<<___;
	movdqu		$Sx[3],($poly,%r10,4)
	movdqu		$Ux,2048($poly,%r10,4)
	add		\$4,%r10
	cmp		\$512,%r10
	jne		.Lsse41_intt_1k_k512
___
	&dump_a(512);
$code.=<<___;
        mov \$1,%eax
	ret
.size	NEWHOPE_poly_intt_1024_sse41,.-NEWHOPE_poly_intt_1024_sse41
___

$code.=<<___;
.align	16
.Lpopcnt_tbl:
.byte	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
.Lnibble_mask:
.byte	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
.byte	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f


.globl	NEWHOPE_binomial_xform
.hidden	NEWHOPE_binomial_xform
.type	NEWHOPE_binomial_xform,\@function,1
.align	16
NEWHOPE_binomial_xform:
	mov	\$512, %rax
	movdqa	.Lpopcnt_tbl(%rip), %xmm3
	movdqa	.Lnibble_mask(%rip), %xmm4
___
$code.=<<___ if ($avx>=2);
        mov     OPENSSL_ia32cap_P+8(%rip),%r10d
	test	\$$feat_avx2,%r10d	# check AVX2
        jnz	.Lbinom_avx2
___
$code.=<<___;
.Lbinom_loop:
	movdqu	(%rsi), %xmm0
	movdqa	%xmm0, %xmm1

	# count the low nibbles
	pand	%xmm4, %xmm1
	movdqa	%xmm3, %xmm2
	pshufb	%xmm1, %xmm2

	# count the high nibbles
	psrlw	\$4, %xmm0
	pand	%xmm4, %xmm0
	movdqa	%xmm3, %xmm1
	pshufb	%xmm0, %xmm1

	# low nibbles - high nibbles
	psubb	%xmm1, %xmm2

	# sum the samples
	movdqa	%xmm2, %xmm1
	pslld	\$8, %xmm1
	paddb	%xmm1, %xmm2
	movdqa	%xmm2, %xmm1
	pslld	\$16, %xmm1
	paddb	%xmm1, %xmm2
	psrad	\$24, %xmm2

	movdqu	%xmm2, (%rdi)
	
	add	\$4*4, %rsi
	add	\$4*4, %rdi
	sub	\$4, %rax
	jnz	.Lbinom_loop
	ret
___
$code.=<<___ if ($avx>=2);
.Lbinom_avx2:
	vinserti128 \$1, %xmm3, %ymm3, %ymm3
	vinserti128 \$1, %xmm4, %ymm4, %ymm4
.Lbinom_avx2_loop:
	vmovdqu	(%rsi), %ymm0

	# count the low nibbles
	vpand	%ymm4, %ymm0, %ymm1
	vpshufb	%ymm1, %ymm3, %ymm1

	# count the high nibbles
	vpsrlw	\$4, %ymm0, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpshufb	%ymm0, %ymm3, %ymm0

	# low nibbles - high nibbles
	vpsubb	%ymm0, %ymm1, %ymm1

	vpslld	\$8, %ymm1, %ymm0
	vpaddb	%ymm1, %ymm0, %ymm1
	vpslld	\$16, %ymm1, %ymm0
	vpaddb	%ymm1, %ymm0, %ymm1
	vpsrad	\$24, %ymm1, %ymm1

	vmovdqu	%ymm1, (%rdi)

	add	\$8*4, %rdi
	add	\$8*4, %rsi
	sub	\$8, %rax
	jnz	.Lbinom_avx2_loop
	vzeroupper
	ret
___

$do_dump = 0;

print $code;

close STDOUT;
