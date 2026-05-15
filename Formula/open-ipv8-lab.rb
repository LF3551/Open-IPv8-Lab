class OpenIpv8Lab < Formula
  include Language::Python::Virtualenv

  desc "Experimental userspace IPv8 toolkit"
  homepage "https://github.com/LF3551/Open-IPv8-Lab"
  url "https://github.com/LF3551/Open-IPv8-Lab/archive/refs/tags/v0.12.8.tar.gz"
  sha256 "a2749aeab853780c4c08989315c86497e40afd2d20fdbd56be2d7cf6c0b51377"
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
