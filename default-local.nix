{ lib, rustPlatform, iproute2, nftables, clang, libbpf, ... }:

rustPlatform.buildRustPackage {
  pname   = "harper";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # eBPF MITM relay (--kernel mode): clang compiles the object, libbpf provides
  # the bpf/linux headers.
  nativeBuildInputs = [ iproute2 nftables clang libbpf ];
  LIBBPF_INCLUDE = "${libbpf}/include";


  meta = with lib; {
    description = "Per-device bandwidth shaping and network traffic management";
    license     = licenses.mit;
    maintainers = [ "Masrkai" ];
    platforms   = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "harper";
  };
}
