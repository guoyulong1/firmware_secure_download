#!/usr/bin/env bash
# Author: GuoYuLong
# 下载与上游 Git 标签对应的官方源码包：
#   openssl/openssl  openssl-3.5.9
#   curl/curl        curl-8_23_0（发布包版本 8.23.0）
# 本机访问 GitHub 时 IPv6 会超时，下载固定走 IPv4。归档与对应 Git 标签一致。

set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
work="${root}/.cache"
mkdir -p "${work}"

have_tag() {
  local dest="$1"
  local tag="$2"
  [[ -f "${dest}/.fsd-source-tag" && "$(cat "${dest}/.fsd-source-tag")" == "${tag}" ]]
}

download() {
  local dest="$1"
  shift
  local url
  for url in "$@"; do
    echo "get ${url}"
    local attempt
    for attempt in 1 2 3 4 5; do
      rm -f "${dest}"
      # codeload 不支持 Range，失败后整包重下，不使用续传。
      if curl --ipv4 --http1.1 -fL --max-time 0 -o "${dest}" "${url}"; then
        return 0
      fi
      echo "retry ${attempt} ${url}" >&2
      sleep 2
    done
    echo "failed ${url}" >&2
    rm -f "${dest}"
  done
  return 1
}

extract_to() {
  local archive="$1"
  local dest="$2"
  local tag="$3"
  rm -rf "${dest}"
  mkdir -p "${dest}"
  case "${archive}" in
    *.zip)
      local unpacked="${work}/unzipped"
      rm -rf "${unpacked}"
      mkdir -p "${unpacked}"
      unzip -q "${archive}" -d "${unpacked}"
      local inner
      inner="$(find "${unpacked}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
      mv "${inner}/." "${dest}/"
      ;;
    *)
      tar -xzf "${archive}" -C "${dest}" --strip-components=1
      ;;
  esac
  printf '%s\n' "${tag}" > "${dest}/.fsd-source-tag"
}

# codeload 提供的是对应 Git 标签的源码归档，这条链路在本机可用。
if have_tag "${root}/openssl" "openssl-3.5.9"; then
  echo "keep openssl openssl-3.5.9"
else
  download "${work}/openssl.tar.gz" \
    "https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-3.5.9" \
    "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"
  extract_to "${work}/openssl.tar.gz" "${root}/openssl" "openssl-3.5.9"
fi

if have_tag "${root}/curl" "curl-8_23_0"; then
  echo "keep curl curl-8_23_0"
else
  download "${work}/curl.tar.gz" \
    "https://codeload.github.com/curl/curl/tar.gz/refs/tags/curl-8_23_0" \
    "https://curl.se/download/curl-8.23.0.tar.gz"
  extract_to "${work}/curl.tar.gz" "${root}/curl" "curl-8_23_0"
fi

echo "openssl $(cat "${root}/openssl/.fsd-source-tag")"
echo "curl $(cat "${root}/curl/.fsd-source-tag")"
