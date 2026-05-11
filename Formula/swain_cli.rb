class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.17"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.16/swain_cli-macos-arm64"
      sha256 "f03ab90ceabd724c290021c8719e9ff0cb54475dd80aaa5e940ddf9e5a000aaa"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.16/swain_cli-macos-x86_64"
      sha256 "5013e48e79ab02764c22eb6d5034fb1edea64b11a29c4bb6c4e4df7d44332630"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.16/swain_cli-linux-arm64"
      sha256 "5aafd5f3c968a69dbe27c3bf06fe776031563d20e213dd3df2874a3eb4412dba"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.16/swain_cli-linux-x86_64"
      sha256 "75b4d7c42e085ad9e0ad1f2becdada7c3b217b34753ff906abf5bbe898b2dab2"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
