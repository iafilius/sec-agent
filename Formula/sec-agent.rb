class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.2.0/sec-agent_v2.2.0_darwin_arm64.tar.gz"
  version "2.2.0"
  sha256 "fb2919ed5ec43e31fa60e2b732527f20df5f8c08da692f022b7dfb12cae3eb29"
  license "GPL-3.0-or-later"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/sec-agent version")
  end
end
