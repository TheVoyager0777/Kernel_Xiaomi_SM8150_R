#!/bin/bash

yellow='\033[0;33m'
white='\033[0m'
red='\033[0;31m'
gre='\e[0;32m'

#
# Enviromental Variables
#

# Set host name
export KBUILD_BUILD_HOST="Voayger-sever"
export KBUILD_BUILD_USER="TheVoyager"

# Set the current branch name
BRANCH=$(git rev-parse --symbolic-full-name --abbrev-ref HEAD)

# Set the last commit sha
COMMIT=$(git rev-parse --short HEAD)

# Set current date
DATE=$(date +"%d.%m.%y")

# Set our directory
OUT_DIR=out/

# Set script config dir
CONFIG=build_config

#Set csum
CSUM=$(cksum <<<${COMMIT} | cut -f 1 -d ' ')

if [ ! -f "${OUT_DIR}Version" ] || [ ! -d "${OUT_DIR}" ]; then
	echo "init Version"
	mkdir -p $OUT_DIR
	echo 1 >${OUT_DIR}Version
fi

#Set build count
BUILD=$(cat out/Version)

# How much kebabs we need? Kanged from @raphielscape :)
if [[ -z "${KEBABS}" ]]; then
	COUNT="$(grep -c '^processor' /proc/cpuinfo)"
	export KEBABS="$((COUNT * 2))"
fi

function enable_flto() {
	scripts/config --file ${OUT_DIR}/.config \
		-e	LTO				\
		-e	LTO_CLANG		\
		-d	THIN_LTO

    	# Make olddefconfig
	cd ${OUT_DIR} || exit
	make -j${KEBABS} ${ARGS} olddefconfig
	cd ../ || exit
}

function enable_tlto() {
	scripts/config --file ${OUT_DIR}/.config \
		-e	LTO				\
		-e	LTO_CLANG		\
		-e	THIN_LTO

    	# Make olddefconfig
	cd ${OUT_DIR} || exit
	make -j${KEBABS} ${ARGS} olddefconfig
	cd ../ || exit
}

function disable_lto() {
	scripts/config --file ${OUT_DIR}/.config \
	-d LTO_CLANG
}

function checkbuild() {
	if [[ ! -f ${OUT_DIR}/arch/arm64/boot/Image-dtb ]] && [[ ! -f ${OUT_DIR}/arch/arm64/boot/Image.gz-dtb ]]; then
		echo "Error in ${os} build!!"
        	git checkout arch/arm64/boot/dts/vendor &>/dev/null
		exit 1
	fi
}

function out_product() {
	find ${OUT_DIR}/$dts_source -name '*.dtb' -exec cat {} + >${OUT_DIR}/arch/arm64/boot/dtb

	mkdir -p anykernel/kernels/$OS
	# Import Anykernel3 folder
	if [[ -f ${OUT_DIR}/arch/arm64/boot/Image.gz-dtb ]]; then
		cp ${OUT_DIR}/arch/arm64/boot/Image.gz-dtb anykernel/kernels/$OS
	else
		if [[ -f ${OUT_DIR}/arch/arm64/boot/Image-dtb ]]; then
			cp ${OUT_DIR}/arch/arm64/boot/Image-dtb anykernel/kernels/$OS
		fi
	fi
	cp ${OUT_DIR}/arch/arm64/boot/dtbo.img anykernel/kernels/$OS

	# If we use a patch script..
	if [[ $PATCH_OUT_PRODUCT_HOOK == 1 ]]; then
		patch_out_product_hook
	fi
}

function clean_up_outfolder() {
	echo "------------ Clean up dts folder ------------"
	git checkout arch/arm64/boot/dts/vendor &>/dev/null
	echo "----------- Cleanup up old output -----------"
	if [[ -f ${OUT_DIR}/arch/arm64/boot/Image ]] && [[ -f ${OUT_DIR}/arch/arm64/boot/Image.gz ]]; then
		rm -r ${OUT_DIR}/arch/arm64/boot/
	fi
	echo "------- Cleanup up previous kernelzip -------"
	if [[ -d anykernel/out/ ]]; then
			rm -r anykernel/out/
			mkdir anykernel/out
	fi
	echo "-------------------- Done! ------------------"
}

function ak3_compress()
{
	cd anykernel || exit

	if [[ ! -d anykernel/out/ ]]; then
			mkdir out
	fi

	zip -r9 "${ZIPNAME}" ./* -x .git .gitignore out/ ./*.zip
	if [[ ! MULTI_BUILD ]]; then
		mkdir out
	fi
	mv *.zip out/
	cd ../
}

function start_build() {
	if [[ ! MULTI_BUILD -eq 1 ]]; then
		clean_up_outfolder
	fi

	# Start Build
	echo "------ Starting ${OS} Build, Device ${DEVICE} ------"

	#
	# Set some variables for further use
	#
	# Let ak3 compress sequence know which system type we use

	if [[ ${OS} == miui ]]; then
		source ./build_config/build.args.MIUI
	elif [[ ${OS} == aosp ]]; then
		source build_config/build.args.AOSP
	elif [[ ${OS} == aospa ]]; then
		source build_config/build.args.AOSPA
	elif [[ ${OS} == custom ]]; then
		source build_config/build.args.CUSTOM
	fi

	source build_config/${PACTH_NAME}

	# Set compiler path
	PATH=${CLANG_PATH}/bin:$PATH
	export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH

	# Make defconfig
	make -j${KEBABS} ${ARGS} "${DEVICE}"_defconfig

	overwrite_config

	# Make olddefconfig
	cd ${OUT_DIR} || exit
	make -j${KEBABS} ${ARGS} CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" olddefconfig
	cd ../ || exit

	if [[ "$@" =~ "flto"* ]]; then
		# Enable LTO
		enable_flto
		make -j${KEBABS} ${ARGS} CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" 2>&1 | tee build.log
	fi

	if [[ "$@" =~ "tlto"* ]]; then
		# Enable LTO
		enable_tlto
		make -j${KEBABS} ${ARGS} CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" 2>&1 | tee build.log
	else
		make -j${KEBABS} ${ARGS} CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" 2>&1 | tee build.log
	fi

	ZIPNAME="MiuiCX-${DEVICE^^}-build${BUILD}-${OS}-${CSUM}-${DATE}.zip"
	export ZIPNAME	

	echo "------ Filename: ${ZIPNAME} ------"

	checkbuild

	out_product

	ak3_compress

	echo "------ Finishing ${OS} Build, Device ${DEVICE} ------"
}

# Complie with a list of specialized devices
function build_by_list() {
	clean_up_outfolder
	while read rows
	do 
   		 DEVICE=$(echo $rows | awk '{print $1}')
   		 OS=$(echo $rows | awk '{print $2}')
   		 start_build
	done < ${LIST}

	git checkout arch/arm64/boot/dts/vendor &>/dev/null
}

#
# Do complie 
#
if [ ! -d "anykernel" ]; then
	git clone https://github.com/TheVoyager0777/AnyKernel3 -b msmnile --depth=1 anykernel
fi

START=$(date +"%s")

if [[ ! "$2" =~ ""* ]] && [[ ! "$1" =~ "list"* ]] && [[ ! "$1" =~ "clean" ]] && [[ ! "$1" =~ "-h" ]]; then
	DEVICE=$1
	OS=$2
	export MULTI_BUILD=0
	start_build
fi

if [[ -a "$1" ]]; then
	export LIST=$1
	echo "---- Detect build list for bulk complie! ----"
	export MULTI_BUILD=1
	build_by_list
fi

END=$(date +"%s")
DIFF=$((END - START))

echo $(($BUILD + 1)) >${OUT_DIR}Version
#
# Finish complie 
#


#
# Functions for help
#

# If you need clean up when complication is manually terminated..
if [[ "$1" =~ "clean" ]]; then
	clean_up_outfolder
fi

#
# Functions for help
#

# Self-introduction function
SELF_INTRO1="   This is a commonized script for kernel building. \
		You can use it to complie single target device \
		or complie multi targets in one command. \
		With this script, you can choose the complie type \
		that your system compatible with to enable \
		some specific configs or flags. \
		It also can automically pack the kernel image \
		and dtb, dtbo with Anykernel to a flashable zip \
		after complie sequence finish. You can also \
		invoke a extra script (To see more information, \
		please see build_config/build.args) \
		after making old defconfig to do some special changes. \
		For more information, see the script usage."

SELF_INTRO2=$(echo "Usage1: bash build-kernel.sh [device_code] [system_type]")
SELF_INTRO3=$(echo "Usage2: bash build-kernel.sh list")
SELF_INTRO4=$(echo "Usage3: bash build-kernel.sh -g [device_codes (separated with space)]")
SELF_INTRO5=$(echo "Usage4: bash build-kernel.sh clean")
SELF_INTRO7=$(echo "-g [device_codes]:           generate a list of device_code for continuous complie")
SELF_INTRO7=$(echo "-clean:                      clean up work folders include dts, complie output and kernelzip")

if [[ "$1" =~ "-h" ]]; then
		echo $SELF_INTRO1;
		echo "          ";
		echo $SELF_INTRO2;
		echo $SELF_INTRO3;
		echo $SELF_INTRO4;
		echo "          ";
		echo $SELF_INTRO5;
		echo $SELF_INTRO7;
fi
