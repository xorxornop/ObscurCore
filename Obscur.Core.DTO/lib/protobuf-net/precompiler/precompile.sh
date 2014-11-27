#!/usr/bin/env bash

# positional arguments/parameters: 
# 1: PROJECT_NAMESPACE
# 2: PROJECT_DIRPATH
# 3: INDLL_PATH
# 4: OUTDLL_PATH
# 5: OUTDLL_TYPE
# 6: PRECOMPILER_EXE
# 7: FRAMEWORK_DIRPATH_ABS

PRECOMP_DIRPATH_ABS="$( cd "$( dirname ${BASH_SOURCE[0]} )" ; pwd )"
cd "${PRECOMP_DIRPATH_ABS}"

PROJECT_NAMESPACE=${1:-"ObscurCore.DTO"}

PROJECT_DIRPATH=${2:-"../../.."} 		# e.g: /lib/protobuf-net/precompiler/
if [[ "${PROJECT_DIRPATH}" == /* ]]
then
	PROJECT_DIRPATH_ABS="${PROJECT_DIRPATH}"
else
	PROJECT_DIRPATH_ABS="$( cd "${PRECOMP_DIRPATH_ABS}/${PROJECT_DIRPATH}"; pwd )"
fi
if [ ! -d "${PROJECT_DIRPATH_ABS}" ]; then
	echo "Project directory path invalid: ${PROJECT_DIRPATH_ABS}"
	echo "Supplied path: ${PROJECT_DIRPATH}"
	exit 1
fi	

function relToAbsPath {
	RTAP_SRC_ABS_PATH=$1
	RTAP_DST_ABS_PATH=$2
	RTAP_COMMON_PART=${RTAP_SRC_ABS_PATH} # for now
	RTAP_RESULT="" # for now

	while [[ "${RTAP_DST_ABS_PATH#$RTAP_COMMON_PART}" == "${RTAP_DST_ABS_PATH}" ]]; do
	    # no match, means that candidate common part is not correct
	    # go up one level (reduce common part)
	    RTAP_COMMON_PART="$(dirname ${RTAP_COMMON_PART})"
	    # and record that we went back, with correct / handling
	    if [[ -z ${RTAP_RESULT} ]]; then
	        RTAP_RESULT=".."
	    else
	        RTAP_RESULT="../${RTAP_RESULT}"
	    fi
	done

	if [[ $RTAP_COMMON_PART == "/" ]]; then
	    # special case for root (no common path)
	    RTAP_RESULT="${RTAP_RESULT}/"
	fi

	# since we now have identified the common part,
	# compute the non-common part
	FORWARD_PART="${RTAP_DST_ABS_PATH#$RTAP_COMMON_PART}"

	# and now stick all parts together
	if [[ -n ${RTAP_RESULT} ]] && [[ -n ${FORWARD_PART} ]]; then
	    RTAP_RESULT="${RTAP_RESULT}${FORWARD_PART}"
	elif [[ -n $FORWARD_PART ]]; then
	    # extra slash removal
	    RTAP_RESULT="${FORWARD_PART:1}"
	fi

	REL_TO_ABS_PATH_RETVAL=$(echo ${RTAP_RESULT})
}

# Input assembly (data-transfer-object class library DLL) paths:
# DTO class library assembly DLL (relative/absolute - supplied argument) : INDLL_PATH
# Directory to which it will be written (absolute) : INDLL_DIRPATH_ABS
# Path for assembly input (directory + file, absolute) : INDLL_FULLPATH_ABS
# As above but relative to script dir: INDLL_FULLPATH_REL_ARG

INDLL_PATHSEGMENT_REL="bin/Release"
INDLL_FILENAME="${PROJECT_NAMESPACE}.dll"
INDLL_PATH=${3:-${INDLL_PATHSEGMENT_REL}/${INDLL_FILENAME}}
if [[ "${INDLL_PATH}" == /* ]]
then
	INDLL_FULLPATH_ABS="${INDLL_PATH}"
else
	INDLL_FULLPATH_ABS="${PROJECT_DIRPATH_ABS}/${INDLL_PATH}"
fi
if [ ! -f "${INDLL_FULLPATH_ABS}" ]; then
	echo "Input assembly path invalid: ${INDLL_FULLPATH_ABS}"
	echo "Supplied path: ${INDLL_PATH}"
	exit 1
fi

relToAbsPath $PRECOMP_DIRPATH_ABS $INDLL_FULLPATH_ABS
INDLL_FULLPATH_REL_ARG=${REL_TO_ABS_PATH_RETVAL}

# Output assembly variables:
# Serialising assembly DLL file (relative/absolute - supplied argument) : OUTDLL_PATH
# Path of directory for assembly output (absolute) : OUTDLL_DIRPATH_ABS
# Path for assembly output (directory + file, absolute) : OUTDLL_FULLPATH_ABS
# Name of serialiser object type in assembly: OUTDLL_TYPE

OUTDLL_DEFAULT_TYPE="DtoSerialiser"
OUTDLL_PATH=${4:-bin/Serialiser/${PROJECT_NAMESPACE}.${DEFAULT_SERIALISER_TYPE}.dll}
if [[ "${OUTDLL_PATH}" == /* ]]
then
	OUTDLL_FULLPATH_ABS="${OUTDLL_PATH}"
else
	OUTDLL_FULLPATH_ABS="${PROJECT_DIRPATH_ABS}/${OUTDLL_PATH}"
fi
OUTDLL_DIRPATH_ABS="$( dirname "${OUTDLL_PATH_ABS}" )"
if [ ! -d "${OUTDLL_DIRPATH_ABS}" ]; then
	if [ ! $( mkdir -p ${OUTDLL_DIRPATH_ABS} ) ]; then
		echo "Output assembly path is invalid: ${OUTDLL_FULLPATH_ABS}"
		echo "Supplied path : ${OUTDLL_PATH}"
		exit 1
	fi
fi
OUTDLL_FULLPATH_ABS_ARG="-o:${OUTDLL_FULLPATH_ABS}"
OUTDLL_TYPE=${5:-${PROJECT_NAMESPACE}.${OUTDLL_DEFAULT_TYPE}}
OUTDLL_TYPE_ARG="-t:${OUTDLL_TYPE}"

FRAMEWORK_DIRPATH_ABS=${6:-"/Library/Frameworks/Mono.framework/Versions/3.10.0/lib/mono/4.5"}
FRAMEWORK_ARG="-f:${FRAMEWORK_DIRPATH_ABS}"

PRECOMPILER_EXE=${7:-"precompile.exe"}

# Call the precompiler executable

mono ${PRECOMPILER_EXE} ${FRAMEWORK_ARG} ${INDLL_FULLPATH_REL_ARG} ${OUTDLL_FULLPATH_ABS_ARG} ${OUTDLL_TYPE_ARG} 

echo "Emitted serialiser asssembly!"
