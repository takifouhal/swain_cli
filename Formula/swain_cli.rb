class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.19"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.19/swain_cli-macos-arm64"
      sha256 "289fe215b8e806e5539d6ef7b194a4756472930ae47a7a75e9d1f2d4d1fb3fa5"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.19/swain_cli-macos-x86_64"
      sha256 "95cec6958ac27d2100132e43735a2bdec74e785c564c5d6123030c177ccf2d59"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.19/swain_cli-linux-arm64"
      sha256 "1bcb9f6a48ab4431afb32080b712968efbc6c7e16c81a023ede85c5fddab5363"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.19/swain_cli-linux-x86_64"
      sha256 "8e0cedc3ece6e4fb941bd8cc097c28470c15b564412280356e34acfa8f07cc4b"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
