class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.15"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.15/swain_cli-macos-arm64"
      sha256 "e16d4e7625c507b4eed8ff28f6311b3aa83d44299cc73867b5e6f7ccef873a6d"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.15/swain_cli-macos-x86_64"
      sha256 "d8ea156eade91bdd37738d524d679d03ca84eadcde1c4a83b76c3f484897e394"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.15/swain_cli-linux-arm64"
      sha256 "dddcc3d75be84cbcb62c95e8a8353dd3b0fb7a33a887210cd461b794a1ae37ec"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.15/swain_cli-linux-x86_64"
      sha256 "920f3852b2e4b9b97fd30b1268f6cfbe62a1e949217e34a8fe8ed36d1f8c66be"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
