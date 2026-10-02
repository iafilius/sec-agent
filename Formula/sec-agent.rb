class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.15.0/sec-agent_v2.15.0_darwin_arm64.tar.gz"
  sha256 "b112a895a2340b48d1f20f4b7209d8f2c4c5a2995677587ffb650669657f3435"
  license "GPL-3.0-or-later"

  depends_on :macos

  def install
    bin.install "sec-agent"
    bin.install_symlink bin/"sec-agent" => "sec"
  end

  post_install_steps do
    run "sec-agent", base: :bin, args: ["restart", "--hot-reload"], must_succeed: false
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/sec-agent version")
  end
end
