# Note: This is officially the package I use for my own configuration.nix for my NixOS system
# while I am confident it will work and this should be on the Nixpkgs. however I do not consent
# for anyone to just take my effort here and publish it anywhere they like, I wish to be the only
# one who controls which platforms, package managers and architectures this gets on, taking notes and learning
# while also gate-keeping, gate-keeping who? the script kiddies, who don't understand systems and vipe codes
# while this project has AI assistance from ideas to solving issues, it's not "vipe coded" explaining methedologies,
# the how and what tools or models are used isn't a productive argument in my very own opinion and I won't answer any questions regarding these
# however I would also like to note that this project is not Anti or Pro AI, it's Anti stupidity and PS from the 3 categories mentioned before

{ lib, rustPlatform, iproute2, nftables, clang, libbpf, fetchFromGitHub, src ? null, ... }:

let
  # Default to fetching from GitHub at a specific commit (like nixvim example)
  # Override with: nix-build -E 'with import <nixpkgs> {}; callPackage ./default.nix { src = lib.cleanSource ./.; }'
  defaultSrc = fetchFromGitHub {
    owner  = "Masrkai";
    repo   = "harper";
    rev    = "3ae33ba533d4a750cdcf0d8d1da59999d6168e83";
    # hash   = lib.fakeHash;  # replace after first failed build
  };

  src = if src == null then defaultSrc else src;
in
rustPlatform.buildRustPackage {
  pname = "harper";
  version = "0.1.2";

  inherit src;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # eBPF MITM relay (--kernel mode): clang compiles the object, libbpf provides
  # the bpf/linux headers.
  nativeBuildInputs = [ iproute2 nftables clang libbpf ];
  LIBBPF_INCLUDE = "${libbpf}/include";

  meta = with lib; {
    description = "bandwidth shaping and network traffic management tool with ebpf";
    license     = licenses.mit;
    maintainers = [ "Masrkai" ];
    platforms   = [ "x86_64-linux" ];
    mainProgram = "harper";
  };
}