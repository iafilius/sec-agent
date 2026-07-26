class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.0.0/sec-agent_v2.0.0_darwin_arm64.tar.gz"
  sha256 "592898291efb459f8f3214dd48ddc78566504d559a0201ada72372e1fad747ff"
  license "MIT"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  test do
    assert_match "v2.0.0", shell_output("#{bin}/sec-agent version")
  end
end
