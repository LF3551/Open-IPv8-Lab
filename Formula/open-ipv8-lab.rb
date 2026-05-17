class OpenIpv8Lab < Formula
  include Language::Python::Virtualenv

  desc "Experimental userspace IPv8 toolkit"
  homepage "https://github.com/LF3551/Open-IPv8-Lab"
  url "https://github.com/LF3551/Open-IPv8-Lab/archive/refs/tags/v0.13.0.tar.gz"
  sha256 "531a29d546ae3574bc8042d33db85bb960eb62fbea183f25cf9c5fa50b4cf709"
  license "Apache-2.0"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    output = shell_output("#{bin}/ipv8lab --help")
    assert_match "Usage", output
  end
end
