class Sbommage < Formula
  desc "Interactive terminal frontend for viewing Software Bill of Materials (SBOM) files"
  homepage "https://github.com/popey/sbommage"
  url "https://github.com/popey/sbommage/archive/refs/tags/v1.0.0.tar.gz"
  sha256 ""  # This will need to be updated when creating actual releases
  license "MIT"

  depends_on "python@3.11"

  resource "textual" do
    url "https://files.pythonhosted.org/packages/source/t/textual/textual-0.85.2.tar.gz"
    sha256 "c876cae596b9de27cfbcddb5fce26b7a30e0e73f2d62b6a3e69c8d61e9f30a55"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    # Test that the command exists and shows help
    system bin/"sbommage", "--help"
  end
end