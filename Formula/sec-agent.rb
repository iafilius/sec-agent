class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.2.0/sec-agent_v2.2.0_darwin_arm64.tar.gz"
  version "2.2.0"
  sha256 "27c9d9f5055dc2b7a1769806b8f1147b7ab60cd4bc9732e0081f167c64aac5b6"
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
