#!/bin/bash

yellow='\033[0;33m'
white='\033[0m'
red='\033[0;31m'
gre='\e[0;32m'

ANYKERNEL3_DIR=$PWD/AnyKernel3
FINAL_KERNEL_ZIP=kernel-Tucana-r-VoyagerIII-$(git rev-parse --short=7 HEAD).zip
IMAGE_GZ=$PWD/out/arch/arm64/boot/Image.gz

export ARCH=arm64
export SUBARCH=arm64
export HEADER_ARCH=arm64
export CLANG_PATH=

export KBUILD_BUILD_HOST="Voayger-sever"
export KBUILD_BUILD_USER="TheVoyager"

ccache_=`which ccache` || {
	ccache_=
	echo -e "${yellow}Warning: ccache is not used! $white"
}

if [ -n "$ccache_" ]; then
	orig_cache_hit_d=$(	ccache -s | grep 'cache hit (direct)'		| awk '{print $4}')
	orig_cache_hit_p=$(	ccache -s | grep 'cache hit (preprocessed)'	| awk '{print $4}')
	orig_cache_miss=$(	ccache -s | grep 'cache miss'			| awk '{print $3}')
	orig_cache_hit_rate=$(	ccache -s | grep 'cache hit rate'		| awk '{print $4 " %"}')
	orig_cache_size=$(	ccache -s | grep '^cache size'			| awk '{print $3 " " $4}')
fi

# make mrproper O=out || exit 1
make raphael_defconfig O=out_raphael || exit 1

Start=$(date +"%s")

make -j$(nproc --all) \
	O=out_raphael \
	CC="${ccache_} clang" \
	AS=llvm-as \
	LD=ld.lld \
	AR=llvm-ar \
	NM=llvm-nm \
	STRIP=llvm-strip \
	OBJCOPY=llvm-objcopy \
	OBJDUMP=llvm-objdump \
	CLANG_TRIPLE=aarch64-linux-gnu- \
	CROSS_COMPILE=/bin/aarch64-linux-gnu- \
	CROSS_COMPILE_ARM32=/bin/arm-linux-gnueabi-

exit_code=$?
End=$(date +"%s")
Diff=$(($End - $Start))

echo -e "$gre << Build completed in $(($Diff / 60)) minutes and $(($Diff % 60)) seconds >> \n $white"

if [ -n "$ccache_" ]; then
		now_cache_hit_d=$(	ccache -s | grep 'cache hit (direct)'		| awk '{print $4}')
		now_cache_hit_p=$(	ccache -s | grep 'cache hit (preprocessed)'	| awk '{print $4}')
		now_cache_miss=$(	ccache -s | grep 'cache miss'			| awk '{print $3}')
		now_cache_hit_rate=$(	ccache -s | grep 'cache hit rate'		| awk '{print $4 " %"}')
		now_cache_size=$(	ccache -s | grep '^cache size'			| awk '{print $3 " " $4}')
		echo -e "${yellow}ccache status:${white}"
		echo -e "\tcache hit (direct)\t\t"     $orig_cache_hit_d    "\t${gre}->${white}\t" $now_cache_hit_d
		echo -e "\tcache hit (preprocessed)\t" $orig_cache_hit_p    "\t${gre}->${white}\t" $now_cache_hit_p
		echo -e "\tcache miss\t\t\t"           $orig_cache_miss     "\t${gre}->${white}\t" $now_cache_miss
		echo -e "\tcache hit rate\t\t\t"       $orig_cache_hit_rate "\t${gre}->${white}\t" $now_cache_hit_rate
		echo -e "\tcache size\t\t\t"           $orig_cache_size     "\t${gre}->${white}\t" $now_cache_size
	fi