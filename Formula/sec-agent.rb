class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.19.4/sec-agent_v2.19.4_darwin_arm64.tar.gz"
  sha256 "be2474e7dad767594e046ad3e20d011775493c6cbec8164295c79c5be7b2b6ee"
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
