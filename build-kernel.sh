#!/bin/bash

#
# Enviromental Variables
#

export SOURCE_ROOT=$(readlink -f $PWD)
export BUILD_CONFIG=${BUILD_CONFIG:-build.config}

# Set host name
export KBUILD_BUILD_HOST="Voayger-server"
export KBUILD_BUILD_USER="TheVoyager"

# Set the last commit sha
COMMIT=$(git rev-parse --short HEAD)

# Set current date
DATE=$(date +"%d.%m.%y")

# Set our directory
OUT_DIR=out/
PRODUCT_DIR=${SOURCE_ROOT}/anykernel

# Set defconfig folder (Root is arch/arm64/configs)
DEFCONFIG_DIR=arch/arm64/configs/

# Set script config dir
ARGS_DIR=build_config

MULTI_BUILD=0

STAT_FILE="${OUT_DIR}/Version"

#Set csum
CSUM=$(cksum <<<"${COMMIT}" | cut -f 1 -d ' ')

# shellcheck source=/dev/null
source ${ARGS_DIR}/build_definitions.global
export FILES

# How much kebabs we need? Kanged from @raphielscape :)
if [[ -z "${KEBABS}" ]]; then
	COUNT="$(grep -c '^processor' /proc/cpuinfo)"
	export KEBABS="$((COUNT * 2))"
fi

PREBUILTS_PATHS=(
LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN
LINUX_GCC_CROSS_COMPILE_ARM32_PREBUILTS_BIN
LINUX_GCC_CROSS_COMPILE_COMPAT_PREBUILTS_BIN
CLANG_PREBUILT_BIN
)

function checkbuild() {
	if [[ ! -f ${OUT_DIR}/arch/arm64/boot/Image ]] && [[ ! -f ${OUT_DIR}/arch/arm64/boot/Image.gz ]]; then
		echo "Error in ${OS} build!!"
        	git checkout arch/arm64/boot/dts/vendor &>/dev/null
		exit 1
	fi
}

function out_product() {
	PRODUCT_OUT=${PRODUCT_DIR}/kernels/"$OS"
	dts_source=arch/arm64/boot/dts

	find ${OUT_DIR}/$dts_source -name '*.dtb' -exec cat {} + >${OUT_DIR}/arch/arm64/boot/dtb

	if [ ! -d "anykernel" ]; then
		git clone https://github.com/TheVoyager0777/AnyKernel3.git -b kona --depth=1 anykernel
	fi

	mkdir -p anykernel/kernels/"$OS"
	cat /dev/null > "${PRODUCT_DIR}"/files

	for FILE in ${FILES}; do
		if [ -f ${OUT_DIR}/"$FILE" ]; then
			filename=$(echo "$FILE" | awk -F "/" '{print $NF}')
			# Copy to target folder
			echo "  $FILE ${PRODUCT_OUT}"
			echo "${PREBUILT_OUT}/$FILE"
			echo "$filename" >> "${PRODUCT_DIR}"/files
			cp -p ${OUT_DIR}/"$FILE" "${PRODUCT_OUT}"/
			echo "$FILE copied to ${PRODUCT_OUT}"
	  	else
			echo "$FILE does not exist, skipping"
		fi
	done

	rm -r ${OUT_DIR}/arch/arm64/boot/

	# If we use a patch script..
	if [[ $PATCH_OUT_PRODUCT_HOOK == 1 ]]; then
		patch_out_product_hook
	fi
}

function clean_up_outfolder() {
	echo "------------ Clean up dts folder ------------"
	git checkout arch/arm64/boot/dts/vendor &>/dev/null
	echo "----------- Cleanup up old output -----------"
	if [[ -d ${OUT_DIR}/arch/arm64/boot/ ]]; then
		rm -r ${OUT_DIR}/arch/arm64/boot/
	fi
	echo "------- Cleanup up previous kernelzip -------"
	if [[ ! MULTI_BUILD -eq 1 ]]; then
		if [[ -d anykernel/out/ ]]; then
			rm -r anykernel/out/
			mkdir anykernel/out
		fi
	fi

	# Cleanup temp
	if [[ -d anykernel/kernels/"${OS}" ]]; then
		rm -r anykernel/kernels/"${OS}"
	fi

	echo "-------------------- Done! ------------------"
}

function ak3_compress()
{
		if [[ ! -d anykernel/out ]]; then
			mkdir anykernel/out
		fi
		cd anykernel || exit
		zip -r9 "${ZIPNAME}" ./* -x .git .gitignore out/ ./*.zip
		mv ./*.zip out/
		cd ../
}

function check_stat_file() {
	#Set build count
	if [ ! -f "${STAT_FILE}" ] || [ ! -d "${OUT_DIR}" ]; then
		echo "init Version"
		mkdir -p $OUT_DIR
		BUILD=1
		echo "BUILD_COUNT=${BUILD}" > ${STAT_FILE}
	fi
}

function stat_print() {
	cat /dev/null > ${STAT_FILE}    #clean all info
	{								#Always Print them
		echo "BUILD_COUNT=${BUILD}"
		echo "IS_MULTI_BUILD=${MULTI_BUILD}"
		echo "DEVICE=${DEVICE}"
		echo "TARGET_OS=${OS}"
		echo "$ZIPNAME" 

		if [[ MULTI_BUILD -eq 1 ]]; then
			echo "LIST_DIR=${device_list}"
		fi
	} >> "${STAT_FILE}" || export ZIPNAME

	#Only when multi compile

}

function pre_compile() {
	GET_BUILD_COUNT=$(awk -F "=" '/BUILD_COUNT/ {print $2}' "${STAT_FILE}")

	BUILD=$GET_BUILD_COUNT

	echo "Current version is $GET_BUILD_COUNT"
	ZIPNAME="Voyager-${DEVICE^^}-build${BUILD}-${OS}-${CSUM}-${DATE}.zip"
	stat_print
}

function post_compile() {
		NEW_COUNT=$((BUILD + 1))
		echo "Next version is $NEW_COUNT"
		cat /dev/null > ${STAT_FILE}
		echo "BUILD_COUNT=${NEW_COUNT}" > ${STAT_FILE}
}

function header_install() {
	echo "======================"
	echo "Installing kernel headers"
	set -x
	(cd ${OUT_DIR} && \
	make HOSTCFLAGS="${TARGET_INCLUDES}" HOSTLDFLAGS="${TARGET_LINCLUDES}" "${ARGS[@]}" headers_install)
	set +x
}

function generate_defconfig() {

	ARCH=arm64 \
	CROSS_COMPILE=aarch64-linux-gnu- \
	CC=clang \
	CLANG_TRIPLE=aarch64-linux-gnu- \
	LD=ld.lld \
	scripts/gki/generate_defconfig.sh vendor/star-qgki_defconfig
}

function start_build() {
	trap "echo aborting.." 2 || exit 1;

	pre_compile

	if [[ MULTI_BUILD -eq 1 ]] && [[ -d ${OUT_DIR}/arch/arm64/boot/ ]]; then
		rm -r ${OUT_DIR}/arch/arm64/boot/
	fi

	# Start Build
	echo "------ Starting ${OS^} Build, Device ${DEVICE^^} ------"

	# shellcheck source=/dev/null
	source build_config/"${PACTH_NAME}"

	cat "${ARGS_DIR}/build.args.${OS^^}"

	# shellcheck source=/dev/null
	. "${ARGS_DIR}/build.args.${OS^^}"

	for PREBUILT_BIN in "${PREBUILTS_PATHS[@]}"; do
	    PREBUILT_BIN=\${${PREBUILT_BIN}}
	    eval PREBUILT_BIN="${PREBUILT_BIN}"
	    if [ -n "${PREBUILT_BIN}" ]; then
	        # Mitigate dup paths
	        PATH=${PATH//"${SOURCE_ROOT}\/${PREBUILT_BIN}:"}
	        PATH=${SOURCE_ROOT}/${ARGS_DIR}/${PREBUILT_BIN}/bin:${PATH}
	    fi
	done
	export PATH

	echo "PATH=${PATH}"

	export CLANG_TRIPLE CROSS_COMPILE CROSS_COMPILE_COMPAT CROSS_COMPILE_ARM32 ${ARGS[1]}

	# Make defconfig
	DEFCONFIG=$(echo ${DEFCONFIG_DIR} | awk -F "arch/arm64/configs/" '{print $2}')
	make -j"${KEBABS}" "${ARGS[@]}" "${DEFCONFIG}"/"${DEVICE}"_defconfig

	overwrite_config

	# Make olddefconfig
	cd ${OUT_DIR} || exit
	make -j"${KEBABS}" "${ARGS[@]}" CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" olddefconfig
	cd ../ || exit

	make -j"${KEBABS}" "${ARGS[@]}" CC="ccache clang" HOSTCC="ccache gcc" HOSTCXX="ccache g++" 2>&1 | tee build.log

	echo "------ Filename: ${ZIPNAME} ------"

	checkbuild

	out_product

	ak3_compress

	echo "------ Finishing ${OS^} Build, Device ${DEVICE^^} ------"
}

# Complie with a list of specialized devices
function new_build_by_list() {
	clean_up_outfolder
	export MULTI_BUILD=1
	check_stat_file
	export LIST=$device_list
	j=$(wc -l "${LIST}" | awk -F " " '{print $1}')

	for ((i=1; i<=j; i++))
	do
		DEVICE=$(awk 'NR=='$i' {print $1}'  "$LIST")
		OS=$(awk 'NR=='$i' {print $2}'  "$LIST")

		git checkout arch/arm64/boot/dts/vendor &>/dev/null
		trap "echo aborting.." 2 || exit 1;
		start_build
	done
	post_compile
}

#
# Do complie 
#

if [[ "$1" ]]; then
	device_list=$(find ${ARGS_DIR} -name "$1")
	supported_device=$(find ${DEFCONFIG_DIR} -name "$1"_defconfig | awk -F "/" '{print $NF}')

	if [[ $device_list ]]; then
		list_name=$(echo "$device_list" | awk -F "/" '{print $2}')
	elif [[ $supported_device ]]; then
		device_name=$(echo "$supported_device" | awk -F "_" '{print $1}')
	fi

	case $1 in
		"$list_name")
			echo "---- Detect build list for bulk complie! ----"
			new_build_by_list
		;;

		"help")
			printf "Usage: 			bash build-kernel.sh [device_code] [system_type] \n
		        bash build-kernel.sh [listfile] \n
		        bash build-kernel.sh clean clean up work folders include dts, complie output and kernelzip"
		;;

		"clean")
			case $2 in
				"outdir")
					if [[ -d ${OUT_DIR} ]]; then
						rm -r ${OUT_DIR}
					fi
				;;

				"kzip")
					clean_up_outfolder
				;;
			esac	
		;;

		"$device_name")
			OS=$2
			TARGET_SYS=$(find ${ARGS_DIR} -name build.args."${OS^^}" | awk -F "/" '{print $2}' | awk -F "." '{print $3}')
			if [[ ! ${TARGET_SYS,,} ]]; then
				echo "There is no args configuration for this system"
			else
				echo "Found args configuration for selected system"
			fi

			case $2 in 
				"${TARGET_SYS,,}")
					trap "echo Abort.." 2
					DEVICE=$1
					clean_up_outfolder
					export MULTI_BUILD=0
					check_stat_file
					start_build
					post_compile
				;;
			esac
		;;
	esac
else
	echo "Argument is needed"
fi
