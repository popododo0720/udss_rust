# eBPF 이용한 패킷 분석

포트 미러링 사용할경우 연결할 인터페이스 Promiscuous Mode 활성화 필요
```
sudo ip link set enp11s0 promisc on
```

## run
```
RUST_LOG=info cargo run
```
