class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.1.8/sec-agent_v2.1.8_darwin_arm64.tar.gz"
  version "2.1.8"
  sha256 "532f5c56a79de5a6a4713aede9883d540914c3fa000f224953a44c17bbca4a5b"
  license "GPL-3.0-or-later"

  depends_on :macos

  def install
    opoo "iafilius/secure_secrets tap is deprecated! Please migrate to central tap: brew tap iafilius/tap"
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  test do
    assert_match "v2.1.8", shell_output("#{bin}/sec-agent version")
  end
end
