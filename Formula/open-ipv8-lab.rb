class OpenIpv8Lab < Formula
  include Language::Python::Virtualenv

  desc "Experimental userspace IPv8 toolkit"
  homepage "https://github.com/LF3551/Open-IPv8-Lab"
  url "https://github.com/LF3551/Open-IPv8-Lab/archive/refs/tags/v0.12.5.tar.gz"
  sha256 "ccd0452efc71b4050f3ec404723c3f4bc267d7913ee442f4d455a40379425bf7"
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
