#!/bin/bash

yellow='\033[0;33m'
white='\033[0m'
red='\033[0;31m'
gre='\e[0;32m'

ANYKERNEL3_DIR=$PWD/AnyKernel3
FINAL_KERNEL_ZIP=kernel-Tucana-r-VoyagerIII-$(git rev-parse --short=7 HEAD).zip
IMAGE_GZ=$PWD/out/arch/arm64/boot/Image.gz
ccache_=`which ccache`
export ARCH=arm64
export SUBARCH=arm64
export HEADER_ARCH=arm64
export CLANG_PATH=

export KBUILD_BUILD_HOST="Voayger-sever"
export KBUILD_BUILD_USER="TheVoyager"

# make mrproper O=out || exit 1
make cepheus_defconfig O=out_cepheus || exit 1

Start=$(date +"%s")

make -j$(nproc --all) \
	O=out_cepheus \
	CC="${ccache_} ${CLANG_PATH}/bin/clang" \
	CLANG_TRIPLE=/bin/aarch64-linux-gnu- \
	CROSS_COMPILE=/bin/aarch64-linux-gnu- \
	CROSS_COMPILE_ARM32=/bin/arm-linux-gnueabi- || > build.log

exit_code=$?
End=$(date +"%s")
Diff=$(($End - $Start))

echo -e "$gre << Build completed in $(($Diff / 60)) minutes and $(($Diff % 60)) seconds >> \n $white"