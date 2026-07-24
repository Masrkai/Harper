# nixos/tests/harper.nix
#
# Declarative end-to-end NixOS VM test exercising Harper MITM eBPF TC relay
# with iperf3 and traffic forwarding assertions.

{ pkgs, ... }:
let
  harper = pkgs.callPackage ./.. {};
in {
  name = "harper-ebpf";

  nodes.router = { pkgs, ... }: {
    networking.firewall.enable = false;
    environment.systemPackages = [ harper pkgs.tcpdump pkgs.iptables ];
    boot.kernelModules = [ "sch_clsact" ];
    boot.kernelPackages = pkgs.linuxPackages_6_6;
  };

  nodes.client = { ... }: { environment.systemPackages = [ pkgs.iperf3 ]; };
  nodes.server = { ... }: { environment.systemPackages = [ pkgs.iperf3 ]; };

  testScript = ''
    router.wait_for_unit("network.target")
    client.wait_for_unit("network.target")
    server.wait_for_unit("network.target")

    router.succeed("harper attach --backend tc --iface eth1 &")

    client.succeed("iperf3 -c server -t 5 -J > /tmp/result.json")
    assert float(client.succeed("jq -r .end.sum_received.bits_per_second /tmp/result.json")) > 1e6
    router.succeed("harper stats --iface eth1 | grep -q 'forwarded=10'")
  '';
}
