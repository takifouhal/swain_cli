class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.18"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.18/swain_cli-macos-arm64"
      sha256 "2dfc303aebd0193b50354bd2cf6183be507cc3c576e8fc29d1e318b8c4b34023"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.18/swain_cli-macos-x86_64"
      sha256 "05be7fb09acb1f91d5d417be2f933c76636b994dff38241a3aed4e66286fe1f1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.18/swain_cli-linux-arm64"
      sha256 "54139f7f90a087b910b8b36d301db1196712e809f7afcf3a34cc1fd2db7302f5"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.18/swain_cli-linux-x86_64"
      sha256 "d9e1176db59ae96f403d4254670b0a8e3e2a9fcb5c0e8b4a4729b166c9bad8e4"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
