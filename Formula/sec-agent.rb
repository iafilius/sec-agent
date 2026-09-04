class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.7.0/sec-agent_v2.7.0_darwin_arm64.tar.gz"
  version "2.7.0"
  sha256 "3089ff0b66dc2dcc2ef0a2404fa10d5e7b1ae82562baecc97f5d07b6c5accf39"
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
