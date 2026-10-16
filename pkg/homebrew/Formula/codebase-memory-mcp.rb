class CodebaseMemoryMcp < Formula
  desc "Fast code intelligence engine for AI coding agents"
  homepage "https://github.com/DeusData/codebase-memory-mcp"
  version "0.12.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/DeusData/codebase-memory-mcp/releases/download/v#{version}/codebase-memory-mcp-darwin-arm64.tar.gz"
      sha256 "1be41a9dd6902e3633eb0b280189117dc3db3be623bdd3dd4c6ea74372b5a50b"
    end
    on_intel do
      url "https://github.com/DeusData/codebase-memory-mcp/releases/download/v#{version}/codebase-memory-mcp-darwin-amd64.tar.gz"
      sha256 "af3beeeaca53204faf350402ddacee04780a53d0fa510dc31941fb5c2202ff35"
    end
  end

  # The static -portable build: the dynamic one needs glibc 2.38, which
  # Ubuntu 22.04, Debian 12 and RHEL 9 do not have.
  on_linux do
    on_arm do
      url "https://github.com/DeusData/codebase-memory-mcp/releases/download/v#{version}/codebase-memory-mcp-linux-arm64-portable.tar.gz"
      sha256 "8e603f32c9c84b5dc5a6b4a0d23516817d5de199e30f8dcc9bdb128c39386cd8"
    end
    on_intel do
      url "https://github.com/DeusData/codebase-memory-mcp/releases/download/v#{version}/codebase-memory-mcp-linux-amd64-portable.tar.gz"
      sha256 "7024e585132760f383e3e25237e2b2ac6f5185f7e466f8dc66a085bb25f8d0be"
    end
  end

  def install
    bin.install "codebase-memory-mcp"
    # Third-party attribution bundle (present in archives since v0.8.1)
    doc.install "THIRD_PARTY_NOTICES.md" if File.exist?("THIRD_PARTY_NOTICES.md")
  end

  def caveats
    <<~EOS
      Run the following to configure your coding agents:
        codebase-memory-mcp install

      To tap this formula directly:
        brew tap deusdata/codebase-memory-mcp https://github.com/DeusData/codebase-memory-mcp
        brew install codebase-memory-mcp
    EOS
  end

  test do
    assert_match "codebase-memory-mcp", shell_output("#{bin}/codebase-memory-mcp --version")
  end
end
