class SecAgent < Formula
  desc "macOS Enclave-Bound Session Agent for Encrypted Secrets"
  homepage "https://github.com/iafilius/sec-agent"
  url "https://github.com/iafilius/sec-agent/releases/download/v2.19.7/sec-agent_v2.19.7_darwin_arm64.tar.gz"
  sha256 "fed0ade328486f419491fda136061f750ddb7980fc78d3a62c3b4f5c457aed2d"
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
