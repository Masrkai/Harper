{ lib, fetchFromGitHub, rustPlatform, iproute2, nftables, clang, libbpf, ... }:

rustPlatform.buildRustPackage {
  pname = "harper";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner  = "Masrkai";
    repo   = "harper";
    rev    = "2c89f330fa605286732b23bfc357e063df216e29";          # or a specific commit hash / tag e.g. "v0.1.0"
    # hash   = "sha256-r9SRB6wYmlQ+7DpeQKKZuKhoKZ4evNU34PwhGv1ChBw=";
    # hash   = lib.fakeHash;    # replace after first failed build
  };

  cargoLock = {
    lockFile = ./Cargo.lock;  # copy your Cargo.lock next to this file
  };

  # eBPF MITM relay (--kernel mode): clang compiles the object, libbpf provides
  # the bpf/linux headers.
  nativeBuildInputs = [ iproute2 nftables clang libbpf ];
  LIBBPF_INCLUDE = "${libbpf}/include";


  # harper needs raw socket access — these let it find system tools at runtime
  # but the build itself doesn't need them
  meta = with lib; {
    description = "Per-device bandwidth shaping and network traffic management";
    license     = licenses.mit;
    maintainers = [ "Masrkai" ];
    platforms   = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "harper";
  };
}
