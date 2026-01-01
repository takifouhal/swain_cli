class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.10"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.10/swain_cli-macos-arm64"
      sha256 "aa14d5c1b0af6531c3b86e10a4e043210334b6f8b4bff9b63655bdcf18275793"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.10/swain_cli-macos-x86_64"
      sha256 "42b4891ed26364a9dda3689a6e56ee3cf95d45666755dfd429b928ab7a40a4cb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.10/swain_cli-linux-arm64"
      sha256 "4b51a99f7f2f1e23780402cdb150154b2b2f6d67d36ba15fae0cb4763c1c36f3"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.10/swain_cli-linux-x86_64"
      sha256 "3bcf62a418748470eec0464e184441e0cb83947245da680290252419ec3928a9"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
