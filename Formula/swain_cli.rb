class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.14"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.14/swain_cli-macos-arm64"
      sha256 "d69bd7e223ad4599b151dc8b9f6910979bdc35f02daef7065c77c2835d93ecbd"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.14/swain_cli-macos-x86_64"
      sha256 "c3d78d824631640c3ff79460cd8e79324093da9b997eb1676673c973cdd52bab"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.14/swain_cli-linux-arm64"
      sha256 "083d10800794b9927dec75070c5c887af0fb1a4bf1640a32c109c96fdcf0af3a"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.14/swain_cli-linux-x86_64"
      sha256 "851726966e5b804aac0c8132523d9246fab70fe02a01d406a12f92669830ec2c"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
