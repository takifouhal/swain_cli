class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.18"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.17/swain_cli-macos-arm64"
      sha256 "c69a05c4573326f71f747db5bd863d333f3bd8ba793518ce2950dcd5e4fe29e8"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.17/swain_cli-macos-x86_64"
      sha256 "8271954add545e5b38a925898ab404ac6abad69f2d99fa0e6af1232b334f8929"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.17/swain_cli-linux-arm64"
      sha256 "0d2b64e20e1b29f8815479a5252b70b9a98606b3f9e01855e7b679dfee6f7a08"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.17/swain_cli-linux-x86_64"
      sha256 "c4ad61a32412922bd3c812d2c34dad9f91d928e027dae68df35b2e2dd2e0f880"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
