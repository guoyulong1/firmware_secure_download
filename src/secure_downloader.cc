// Copyright 2026 GuoYuLong. All rights reserved.
// Author: GuoYuLong

#include "fsd/secure_downloader.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

#include "fsd/http_client.h"
#include "fsd/md5.h"
#include "fsd/sha256.h"
#include "fsd/text_util.h"

namespace fsd {
namespace {

class UniqueFd {
 public:
  explicit UniqueFd(int fd) noexcept : fd_(fd) {}
  ~UniqueFd() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  [[nodiscard]] int get() const noexcept { return fd_; }

 private:
  int fd_;
};

std::filesystem::path PartialPath(const std::filesystem::path& output) {
  return std::filesystem::path(output.string() + ".part");
}

struct ExpectedDigests {
  std::string sha256;
  std::string md5;
};

struct VerifiedDigests {
  std::string sha256;
  std::string md5;
};

constexpr std::string_view kHttpsScheme = "https://";
constexpr std::size_t kMaxUrlLength = 2048;
// RFC 4291 §2.2 带 IPv4 尾的最长文本是 45 个字符：
// xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255
constexpr std::size_t kMaxIpv6TextLength = 45;

bool IsHexDigit(char ch) {
  return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
         (ch >= 'A' && ch <= 'F');
}

bool IsIpv4(std::string_view host) {
  int octets = 0;
  while (!host.empty()) {
    const std::size_t dot = host.find('.');
    const bool last = dot == std::string_view::npos;
    const std::string_view piece = last ? host : host.substr(0, dot);
    if (piece.empty() || piece.size() > 3 ||
        (piece.size() > 1 && piece.front() == '0')) {
      return false;
    }
    int value = 0;
    for (const char ch : piece) {
      if (ch < '0' || ch > '9') {
        return false;
      }
      value = value * 10 + (ch - '0');
    }
    if (value > 255) {
      return false;
    }
    ++octets;
    if (last) {
      break;
    }
    host.remove_prefix(dot + 1);
    if (host.empty()) {
      return false;
    }
  }
  return octets == 4;
}

// 解析 :: 的一侧。IPv4 尾只允许出现在整个地址的末尾。
bool ParseIpv6Side(std::string_view side, bool allow_ipv4, int* groups) {
  *groups = 0;
  if (side.empty()) {
    return true;
  }
  while (!side.empty()) {
    const std::size_t colon = side.find(':');
    const bool last = colon == std::string_view::npos;
    const std::string_view piece = last ? side : side.substr(0, colon);
    if (piece.empty()) {
      return false;
    }
    if (piece.find('.') != std::string_view::npos) {
      if (!allow_ipv4 || !last || !IsIpv4(piece)) {
        return false;
      }
      *groups += 2;
    } else {
      if (piece.size() > 4) {
        return false;
      }
      for (const char ch : piece) {
        if (!IsHexDigit(ch)) {
          return false;
        }
      }
      *groups += 1;
    }
    if (last) {
      break;
    }
    side.remove_prefix(colon + 1);
    if (side.empty()) {
      return false;
    }
  }
  return true;
}

bool IsIpv6(std::string_view host) {
  if (host.empty() || host.size() > kMaxIpv6TextLength) {
    return false;
  }
  const std::size_t mark = host.find("::");
  const bool compressed = mark != std::string_view::npos;
  if (compressed && host.find("::", mark + 2) != std::string_view::npos) {
    return false;
  }
  int left = 0;
  int right = 0;
  if (!compressed) {
    return ParseIpv6Side(host, true, &left) && left == 8;
  }
  // IPv4 尾只能在右侧，左侧出现点分地址不是合法写法。
  if (!ParseIpv6Side(host.substr(0, mark), false, &left) ||
      !ParseIpv6Side(host.substr(mark + 2), true, &right)) {
    return false;
  }
  // :: 至少要顶替一组零，所以显式组数必须小于 8。
  return left + right < 8;
}

bool IsDnsName(std::string_view host) {
  if (host.empty() || host.size() > 253) {
    return false;
  }
  if (host.back() == '.') {
    host.remove_suffix(1);
    if (host.empty() || host.size() > 253) {
      return false;
    }
  }
  int label_length = 0;
  char previous = '.';
  for (const char ch : host) {
    if (ch == '.') {
      if (label_length == 0 || previous == '-') {
        return false;
      }
      label_length = 0;
      previous = ch;
      continue;
    }
    const bool alnum = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                       (ch >= '0' && ch <= '9');
    if (!alnum && ch != '-') {
      return false;
    }
    if (label_length == 0 && ch == '-') {
      return false;
    }
    if (++label_length > 63) {
      return false;
    }
    previous = ch;
  }
  return label_length > 0 && previous != '-';
}

// 空串被 ParseUint64 拒绝。"080" 按十进制收成 80，符合 RFC 3986 的 *DIGIT。
// 端口没有 IPv4 那种八进制歧义，所以保留前导零。
bool IsPort(std::string_view port) {
  const std::optional<std::uint64_t> value = ParseUint64(port);
  return value.has_value() && *value >= 1 && *value <= 65535;
}

Status InvalidHost() {
  return Status::Failure(ErrorCode::kInvalidArgument, "URL host is invalid");
}

Status ValidateAuthority(std::string_view authority) {
  if (authority.empty()) {
    return InvalidHost();
  }
  if (authority.find('@') != std::string_view::npos) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "URL contains user info that does not belong in a "
                           "firmware URL");
  }

  std::string_view host;
  std::optional<std::string_view> port;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos) {
      return InvalidHost();
    }
    host = authority.substr(1, close - 1);
    const std::string_view tail = authority.substr(close + 1);
    if (!tail.empty()) {
      if (tail.front() != ':') {
        return InvalidHost();
      }
      port = tail.substr(1);
    }
    if (!IsIpv6(host)) {
      return InvalidHost();
    }
  } else {
    const std::size_t colon = authority.find(':');
    if (colon == std::string_view::npos) {
      host = authority;
    } else if (authority.find(':', colon + 1) != std::string_view::npos) {
      return InvalidHost();
    } else {
      host = authority.substr(0, colon);
      port = authority.substr(colon + 1);
    }
    // 只含数字和点就按 IPv4 检查。999.1.1.1 这类看起来像地址但不合法的写法
    // 直接拒绝，不退回 DNS 名称。
    const bool dotted_decimal =
        !host.empty() &&
        host.find_first_not_of("0123456789.") == std::string_view::npos;
    if (host.empty() || (dotted_decimal ? !IsIpv4(host) : !IsDnsName(host))) {
      return InvalidHost();
    }
  }
  if (port.has_value() && !IsPort(*port)) {
    return Status::Failure(ErrorCode::kInvalidArgument, "URL port is invalid");
  }
  return Status::Ok();
}

// curl 会把非法的 % 序列原样发出，所以 path、query、fragment 在这里拦截。
Status ValidatePercentEncoding(std::string_view text) {
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (text[index] != '%') {
      continue;
    }
    if (index + 2 >= text.size() || !IsHexDigit(text[index + 1]) ||
        !IsHexDigit(text[index + 2])) {
      return Status::Failure(ErrorCode::kInvalidArgument,
                             "URL contains an invalid percent-encoding");
    }
    index += 2;
  }
  return Status::Ok();
}

Status ValidateUrl(std::string_view url) {
  if (url.size() < kHttpsScheme.size() || url.size() > kMaxUrlLength) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "URL length is invalid");
  }
  for (const char ch : url) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte <= 0x20 || byte >= 0x7F) {
      return Status::Failure(ErrorCode::kInvalidArgument,
                             "URL contains whitespace, a control character, or "
                             "a non-ASCII byte");
    }
  }
  if (!StartsWithIgnoreCase(url, kHttpsScheme)) {
    return Status::Failure(
        ErrorCode::kProtocol,
        "firmware packages can be downloaded only over HTTPS");
  }

  const std::string_view rest = url.substr(kHttpsScheme.size());
  std::size_t authority_end = rest.size();
  for (const char boundary : {'/', '?', '#'}) {
    const std::size_t pos = rest.find(boundary);
    if (pos != std::string_view::npos) {
      authority_end = std::min(authority_end, pos);
    }
  }
  if (Status status = ValidateAuthority(rest.substr(0, authority_end));
      !status.ok()) {
    return status;
  }
  return ValidatePercentEncoding(rest.substr(authority_end));
}

Status ValidateOptions(const DownloadOptions& options,
                       ExpectedDigests* expected) {
  if (Status status = ValidateUrl(options.url); !status.ok()) {
    return status;
  }
  if (options.output_path.empty()) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "an output path is required");
  }
  const std::optional<std::string> sha256 =
      options.expected_sha256.empty()
          ? std::optional<std::string>{}
          : NormalizeSha256Hex(options.expected_sha256);
  if (!options.expected_sha256.empty() && !sha256.has_value()) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "expected SHA-256 must be 64 hexadecimal digits");
  }
  const std::optional<std::string> md5 =
      options.expected_md5.empty() ? std::optional<std::string>{}
                                   : NormalizeMd5Hex(options.expected_md5);
  if (!options.expected_md5.empty() && !md5.has_value()) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "expected MD5 must be 32 hexadecimal digits");
  }
  if (options.max_bytes == 0) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "the size limit must be greater than 0");
  }
  if (options.expected_size.has_value() &&
      *options.expected_size > options.max_bytes) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "declared size exceeds the size limit");
  }
  if (options.connect_timeout_seconds <= 0 ||
      options.connect_timeout_seconds > 600) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "connect timeout must be between 1 and 600 seconds");
  }
  if (options.transfer_timeout_seconds <= 0 ||
      options.transfer_timeout_seconds > 86400) {
    return Status::Failure(
        ErrorCode::kInvalidArgument,
        "transfer timeout must be between 1 and 86400 seconds");
  }
  if (options.connect_timeout_seconds > options.transfer_timeout_seconds) {
    return Status::Failure(
        ErrorCode::kInvalidArgument,
        "connect timeout cannot exceed the transfer timeout");
  }
  if (options.max_redirects < 0 || options.max_redirects > 20) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "redirect count must be between 0 and 20");
  }
  if (options.user_agent.empty() || options.user_agent.size() > 256) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "User-Agent is empty or too long");
  }
  for (const char ch : options.user_agent) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20 || byte == 0x7F) {
      return Status::Failure(ErrorCode::kInvalidArgument,
                             "User-Agent contains a control character");
    }
  }
  if (!options.ca_file.empty()) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(options.ca_file, error) || error) {
      return Status::Failure(ErrorCode::kIo,
                             "CA file does not exist or is not readable");
    }
  }
  if (!options.pinned_public_key.empty()) {
    if (options.pinned_public_key.size() > 512 ||
        options.pinned_public_key.find_first_of(" \t\r\n") !=
            std::string::npos) {
      return Status::Failure(ErrorCode::kInvalidArgument,
                             "public key pin is invalid");
    }
  }
  expected->sha256 = sha256.value_or("");
  expected->md5 = md5.value_or("");
  return Status::Ok();
}

Status VerifyFileDigests(const std::filesystem::path& path,
                         const ExpectedDigests& expected,
                         VerifiedDigests* verified) {
  VerifiedDigests result;
  if (!expected.sha256.empty()) {
    const Sha256Digest digest = HashFile(path);
    if (!digest.status.ok()) {
      return digest.status;
    }
    if (!DigestsEqual(digest.hex, expected.sha256)) {
      return Status::Failure(ErrorCode::kChecksumMismatch,
                             "SHA-256 mismatch. Expected " + expected.sha256 +
                                 ", actual " + digest.hex +
                                 ". The temporary file was removed");
    }
    result.sha256 = digest.hex;
  }
  if (!expected.md5.empty()) {
    const Md5Digest digest = HashFileMd5(path);
    if (!digest.status.ok()) {
      return digest.status;
    }
    if (!Md5DigestsEqual(digest.hex, expected.md5)) {
      return Status::Failure(ErrorCode::kChecksumMismatch,
                             "MD5 mismatch. Expected " + expected.md5 +
                                 ", actual " + digest.hex +
                                 ". The temporary file was removed");
    }
    result.md5 = digest.hex;
  }
  *verified = std::move(result);
  return Status::Ok();
}

Status PrepareDestination(const DownloadOptions& options) {
  std::error_code error;
  if (std::filesystem::is_directory(options.output_path, error)) {
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "output path is a directory");
  }
  if (std::filesystem::exists(options.output_path, error) && !options.force) {
    return Status::Failure(
        ErrorCode::kIo,
        "output file already exists; pass --force to replace it");
  }

  std::filesystem::path parent = options.output_path.parent_path();
  if (parent.empty()) {
    parent = ".";
  }
  std::filesystem::create_directories(parent, error);
  if (error) {
    return Status::Failure(
        ErrorCode::kIo,
        "cannot create the output directory: " + error.message());
  }
  return Status::Ok();
}

void RemoveQuietly(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
}

Status SyncDirectory(const std::filesystem::path& directory) {
  UniqueFd fd(::open(directory.c_str(), O_RDONLY | O_DIRECTORY));
  if (fd.get() < 0) {
    return Status::Failure(ErrorCode::kIo,
                           ErrnoMessage("cannot open the output directory"));
  }
  if (::fsync(fd.get()) != 0) {
    return Status::Failure(ErrorCode::kIo,
                           ErrnoMessage("cannot sync the output directory"));
  }
  return Status::Ok();
}

Status Publish(const std::filesystem::path& part,
               const DownloadOptions& options, std::uint64_t bytes,
               const VerifiedDigests& digests, std::string_view effective_url) {
  std::error_code error;
  // 固件包是数据文件。去掉可执行位，避免把下载物直接当成程序跑起来。
  std::filesystem::permissions(part,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write |
                                   std::filesystem::perms::group_read |
                                   std::filesystem::perms::others_read,
                               std::filesystem::perm_options::replace, error);
  if (error) {
    std::cerr << "warning: failed to reset file permissions ("
              << error.message()
              << "); the verified content will still be published\n";
  }

  if (std::filesystem::exists(options.output_path, error) && !options.force) {
    return Status::Failure(
        ErrorCode::kIo,
        "output file appeared before publish; the temporary file was kept");
  }
  std::filesystem::rename(part, options.output_path, error);
  if (error) {
    return Status::Failure(
        ErrorCode::kIo,
        "failed to publish the firmware package: " + error.message());
  }

  std::filesystem::path parent = options.output_path.parent_path();
  if (parent.empty()) {
    parent = ".";
  }
  // 文件内容在改名前已经 fsync。目录项落盘失败只告警，避免脚本把
  // 已经发布成功的固件包当成失败再重试一次。
  if (Status status = SyncDirectory(parent); !status.ok()) {
    std::cerr << "warning: " << status.message() << '\n';
  }

  const std::string name = options.package_name.empty()
                               ? std::string("unnamed package")
                               : options.package_name;
  const bool verified = !digests.sha256.empty() || !digests.md5.empty();
  std::cout << (verified ? "firmware package verified\n"
                         : "firmware package saved\n")
            << "  name: " << name << '\n'
            << "  path: " << options.output_path.string() << '\n'
            << "  size: " << bytes << " bytes\n";
  if (!digests.sha256.empty()) {
    std::cout << "  SHA-256: " << digests.sha256 << '\n';
  }
  if (!digests.md5.empty()) {
    std::cout << "  MD5: " << digests.md5 << '\n';
  }
  std::cout << "  final URL: " << effective_url << '\n';
  if (!digests.sha256.empty()) {
    std::cout << "  note: TLS and SHA-256 checks passed. Publisher signature "
                 "verification is separate.\n";
  } else if (!digests.md5.empty()) {
    std::cout << "  note: TLS and MD5 checks passed. MD5 is weaker than "
                 "SHA-256, and publisher signature verification is separate.\n";
  }
  return Status::Ok();
}

Status DownloadOnce(const DownloadOptions& options,
                    const std::filesystem::path& part,
                    std::uint64_t resume_from, HttpResult* result) {
  HttpRequest request;
  request.url = options.url;
  request.destination = part;
  request.resume_from = resume_from;
  request.max_bytes = options.max_bytes;
  request.expected_size = options.expected_size;
  request.connect_timeout_seconds = options.connect_timeout_seconds;
  request.transfer_timeout_seconds = options.transfer_timeout_seconds;
  request.max_redirects = options.max_redirects;
  request.ca_file = options.ca_file;
  request.pinned_public_key = options.pinned_public_key;
  request.user_agent = options.user_agent;

  HttpClient client;
  return client.Download(request, result);
}

}  // namespace

Status SecureDownloader::Download(const DownloadOptions& options) const {
  ExpectedDigests expected;
  if (Status status = ValidateOptions(options, &expected); !status.ok()) {
    return status;
  }
  if (Status status = PrepareDestination(options); !status.ok()) {
    return status;
  }

  const std::filesystem::path part = PartialPath(options.output_path);
  std::uint64_t resume_from = 0;
  std::error_code error;
  if (options.resume && std::filesystem::exists(part, error)) {
    const auto existing = std::filesystem::file_size(part, error);
    if (error) {
      return Status::Failure(
          ErrorCode::kIo,
          "cannot read the temporary file size: " + error.message());
    }
    if (existing > options.max_bytes) {
      return Status::Failure(ErrorCode::kSizeLimit,
                             "existing temporary file exceeds the size limit");
    }
    if (options.expected_size.has_value() &&
        existing > *options.expected_size) {
      RemoveQuietly(part);
    } else if (options.expected_size.has_value() &&
               existing == *options.expected_size &&
               (!expected.sha256.empty() || !expected.md5.empty())) {
      VerifiedDigests verified;
      const Status matched = VerifyFileDigests(part, expected, &verified);
      if (matched.ok()) {
        return Publish(part, options, existing, verified, options.url);
      }
      if (matched.code() != ErrorCode::kChecksumMismatch) {
        return matched;
      }
      // 长度碰巧相同但摘要不对，这段前缀不能再续。
      std::cerr << "temporary file has the declared size but the digest does "
                   "not match; discarding it and downloading again\n";
      RemoveQuietly(part);
    } else if (existing > 0) {
      resume_from = existing;
    }
  }

  std::cerr << "starting firmware download\n"
            << "  URL: " << options.url << '\n'
            << "  temporary file: " << part.string() << '\n';
  if (!expected.sha256.empty()) {
    std::cerr << "  expected SHA-256: " << expected.sha256 << '\n';
  }
  if (!expected.md5.empty()) {
    std::cerr << "  expected MD5: " << expected.md5 << '\n';
  }
  std::cerr << "  resume offset: " << resume_from << '\n'
            << "  TLS certificate and hostname verification: on, TLS 1.2 "
               "minimum, HTTPS only\n";

  HttpResult transferred;
  Status transfer = DownloadOnce(options, part, resume_from, &transferred);
  if (!transfer.ok() && resume_from > 0 &&
      transfer.code() == ErrorCode::kRangeNotSupported) {
    std::cerr << "server did not provide a usable range; downloading the full "
                 "file\n";
    RemoveQuietly(part);
    resume_from = 0;
    transfer = DownloadOnce(options, part, 0, &transferred);
  }
  if (!transfer.ok()) {
    // 摘要还没算。网络中断且用户要求续传时保留前缀；其余失败删掉，
    // 避免下一次把不可信的半包当成进度。
    if (!options.resume || transfer.code() == ErrorCode::kInvalidArgument ||
        transfer.code() == ErrorCode::kSizeLimit ||
        transfer.code() == ErrorCode::kProtocol) {
      RemoveQuietly(part);
    }
    return transfer;
  }

  if (options.expected_size.has_value() &&
      transferred.bytes_on_disk != *options.expected_size) {
    RemoveQuietly(part);
    return Status::Failure(ErrorCode::kInvalidArgument,
                           "downloaded size " +
                               std::to_string(transferred.bytes_on_disk) +
                               " does not match declared size " +
                               std::to_string(*options.expected_size));
  }

  VerifiedDigests verified;
  if (!expected.sha256.empty() || !expected.md5.empty()) {
    if (Status status = VerifyFileDigests(part, expected, &verified);
        !status.ok()) {
      RemoveQuietly(part);
      return status;
    }
  }
  return Publish(part, options, transferred.bytes_on_disk, verified,
                 transferred.effective_url);
}

}  // namespace fsd
