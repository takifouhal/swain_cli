class SwainCli < Formula
  desc "Zero-setup SDK generator built on top of OpenAPI Generator"
  homepage "https://github.com/takifouhal/swain_cli"
  version "0.3.5"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.5/swain_cli-macos-arm64"
      sha256 "6ff269aad0342f78a1e2dbf6f6f25e79ed03704cd9c54096c67a928bf066da96"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.5/swain_cli-macos-x86_64"
      sha256 "52b35f95fa9138ac0cde63e99e4cca9cdf8696dfde4dee2816b5fe9f6eafb931"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.5/swain_cli-linux-arm64"
      sha256 "bbc9c24981fe810428d88f8d652ff451b655189b118db40b218a20c5682f2bae"
    else
      url "https://github.com/takifouhal/swain_cli/releases/download/v0.3.5/swain_cli-linux-x86_64"
      sha256 "4266dad01e35c6546b97c12a3608b377ec10f741244dd085d829f1cce7371464"
    end
  end

  def install
    bin.install Dir["swain_cli*"].first => "swain_cli"
  end

  test do
    assert_match "swain_cli", shell_output("#{bin}/swain_cli --help")
  end
end
