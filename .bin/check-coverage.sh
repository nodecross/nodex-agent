#!/bin/bash

set -ue

## DEFINE COMMANDS
BC='bc'
SED='sed'
NPM='npm'
YARN='yarn'

## DEFINE CONSTS
_0=0
_100=100

function EXIT_USAGE() {
    {   echo "usage: ${0} <threshold> <lcov-path>"
        echo ""
        echo "o <threshold>: 0 - 100"
        echo "o <lcov-path>: your-lcov-path"
    } >&2

    exit -1
}

function EXIT_SUCCESS() {
    [[ ${#} > 0 ]] && {
        echo "${@}" >&1
    }

    exit 0
}

function EXIT_FAILURE() {
    [[ ${#} > 0 ]] && {
        echo "${@}" >&2
    }

    exit 1
}

## CHECK FOR ARGUMENTS
[[ ${#} != 2 ]] && {
    EXIT_USAGE
}

THRESHOLD="${1}"
LCOV_PATH="${2}"

[[ -f "${LCOV_PATH}" ]] || {
    EXIT_FAILURE "(ERROR): '${LCOV_PATH}' file not found and/or not a file"
}

IS_NUM="$(
    echo "${THRESHOLD}" |
    sed -r -n -e "s|^[\-]{0,1}[0-9]{1,}$|OK|p"
)"

[[ "X${IS_NUM}" == "XOK" ]] || {
    EXIT_FAILURE "(ERROR): '${THRESHOLD}' is not a number."
}

[[ ${THRESHOLD} -lt ${_0} ]] && {
    EXIT_FAILURE "(ERROR): Must be set to a number greater than or equal to ${_0}."
}
[[ ${THRESHOLD} -gt ${_100} ]] && {
    EXIT_FAILURE "(ERROR): Must be set to a number less than or equal to ${_100}."
}

## INSTALL CHECK FOR `lcov-summary`
${NPM} exec which "lcov-summary" > /dev/null || {
    EXIT_FAILURE "(ERROR): 'lcov-summary' command not found."
}

## CHECK FOR COVERAGE
COVERAGE="$(
    ${YARN} run lcov-summary "${LCOV_PATH}" |
    ${SED} -r -n -e "s|^.*Total Coverage:  ([0-9]{2}.[0-9]{2})%.*$|\1|p"
)"

[[ "X${COVERAGE}" == "X" ]] && {
    EXIT_FAILURE "(ERROR): Could not derived coverage rate."
}

IS_PASSED="$(
    echo "${THRESHOLD} < ${COVERAGE}" |
    ${BC} |
    ${SED} -r -n -e "s|^1$|OK|p"
)"

[[ "X${IS_PASSED}" != "XOK" ]] && {
    EXIT_FAILURE "(ERROR): Test result has not reached threshold (threshold rate = ${THRESHOLD} %, coverage rate = ${COVERAGE} %)."
}

EXIT_SUCCESS "[^_^] SUCCESS !"
