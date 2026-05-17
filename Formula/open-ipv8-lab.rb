class OpenIpv8Lab < Formula
  include Language::Python::Virtualenv

  desc "Experimental userspace IPv8 toolkit"
  homepage "https://github.com/LF3551/Open-IPv8-Lab"
  url "https://github.com/LF3551/Open-IPv8-Lab/archive/refs/tags/v0.12.9.tar.gz"
  sha256 "c67c0e96289d78518ac7328b31ae5be1132b08eb7dc9ba576482d07bb467c73d"
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
