class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.11.0/sec-agent_v2.11.0_darwin_arm64.tar.gz"
  version "2.11.0"
  sha256 "33e022755d0427dc9dcc7af0d0b55fc05b6aa66864cc96ad62cb65d40f73ca47"
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
