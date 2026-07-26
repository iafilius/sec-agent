class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.1.0/sec-agent_v2.1.0_darwin_arm64.tar.gz"
  version "2.1.0"
  sha256 "f0e9efdadc96575f58e49125b10528073c7ea6b578cf5ef093ce5cd18ae22ad2"
  license "MIT"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  test do
    assert_match "v2.1.0", shell_output("#{bin}/sec-agent version")
  end
end
