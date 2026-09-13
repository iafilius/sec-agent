class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.13.0/sec-agent_v2.13.0_darwin_arm64.tar.gz"
  version "2.13.0"
  sha256 "67f647be445b5485d160e088eb214c543413edf24e6e1db47e7020bc9989d8c4"
  license "GPL-3.0-or-later"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  def post_install
    system "#{bin}/sec-agent", "restart", "--hot-reload" rescue nil
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/sec-agent version")
  end
end
