# frozen_string_literal: true

# A filesystem-backed Homebrew DSL fixture. It executes the rendered install
# method without Homebrew, network access, or native release executables.
require "fileutils"
require "pathname"
require "tmpdir"

module OS
  def self.mac?
    ENV.fetch("FIXTURE_OS") == "mac"
  end
end

class Pathname
  def install(*sources)
    mkpath
    sources.each { |source| FileUtils.cp(source, self/source.to_s) }
  end

  def install_symlink(source)
    mkpath
    FileUtils.ln_s(source, self/source.basename)
  end
end

class Formula
  def self.test
    # Formula runtime tests are exercised by native Homebrew CI.
  end

  def self.method_missing(*)
    # Formula metadata is unrelated to filesystem installation.
  end

  def self.respond_to_missing?(*)
    true
  end

  attr_reader :prefix, :commands

  def initialize(prefix)
    @prefix = Pathname(prefix)
    @commands = []
  end

  def bin = prefix/"bin"
  def lib = prefix/"lib"
  def share = prefix/"share"

  def system(*args)
    @commands << args.map(&:to_s)
    raise "signature verification rejected" if ENV["REJECT_SIGNATURE"] == "1"
  end
end

load ARGV.fetch(0)
names = %w[mvmctl mvm-host-agent mvm-signer-helper mvm-network-endpoint mvm-broker mvm-audit-signer mvm-gpu-endpoint]
names << "mvm-hvf-supervisor" if OS.mac?
library = OS.mac? ? "libmvm_hostlib.dylib" : "libmvm_hostlib.so"
payload = names + [library]

def check(condition, message)
  raise message unless condition
end

Dir.mktmpdir("homebrew-install") do |tmp|
  Dir.chdir(tmp) do
    payload.each { |name| File.binwrite(name, "signed immutable fixture: #{name}\0") }
    File.write("mvm-libkrun-supervisor", "must not ship")
    formula = Mvmctl.new(File.join(tmp, "prefix"))
    formula.install
    destination = formula.lib/"mvmctl"
    payload.each do |name|
      check((destination/name).binread == File.binread(name), "bytes changed: #{name}")
    end
    names.each do |name|
      check((formula.bin/name).symlink?, "missing public symlink: #{name}")
      check((formula.bin/name).realpath == (destination/name).realpath, "wrong symlink: #{name}")
    end
    check((formula.lib/library).realpath == (destination/library).realpath, "hostlib discovery link")
    check((formula.share/"mvmctl/package-managed").read == "homebrew\n", "updater guard")
    check(!(destination/"mvm-libkrun-supervisor").exist?, "optional supervisor shipped")
    check(!(destination/"guest-runtime").exist?, "runtime must use verified fetch")
    if OS.mac?
      checks = formula.commands.select { |args| args.first == "/usr/bin/codesign" }
      check(checks.length == payload.length, "not every Mach-O verified")
      check(checks.all? { |args| args.include?("--verify") && args.include?("--strict") }, "missing strict verification")
      check(checks.none? { |args| args.include?("--sign") || args.include?("--force") }, "release was re-signed")
      check(formula.commands.count { |args| args.first == "/usr/sbin/spctl" } == 2, "notarization assessment")
      ENV["REJECT_SIGNATURE"] = "1"
      begin
        Mvmctl.new(File.join(tmp, "rejected")).install
        raise "signature rejection was ignored"
      rescue RuntimeError => error
        raise unless error.message == "signature verification rejected"
      ensure
        ENV.delete("REJECT_SIGNATURE")
      end
    else
      check(formula.commands.empty?, "mac signing command on Linux")
    end

    payload.each_with_index do |missing, index|
      File.rename(missing, "#{missing}.saved")
      begin
        Mvmctl.new(File.join(tmp, "missing-#{index}")).install
        raise "missing payload accepted: #{missing}"
      rescue Errno::ENOENT
        # Required release payloads must fail closed.
      ensure
        File.rename("#{missing}.saved", missing)
      end
    end
  end
end
puts "installation fixture passed: #{ENV.fetch('FIXTURE_OS')}"
