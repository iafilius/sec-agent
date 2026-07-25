class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v1.9.5/sec-agent_v1.9.5_darwin_arm64.tar.gz"
  sha256 "8f7c0f7829d0b67e7d18a243b556050385432231d1493fe5f8d3e3717d2d941c"
  license "MIT"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  test do
    assert_match "v1.9.5", shell_output("#{bin}/sec-agent version")
  end
end
