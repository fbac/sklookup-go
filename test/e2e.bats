#!/usr/bin/env bats

@test "nc to main TCP socket 7777" {
  nc -zv 127.0.0.1 7777 &> /dev/null
  [ "$?" -eq 0 ]
}

@test "nc to eBPF sk_lookup 5050" {
  nc -zv 127.0.0.1 5050 &> /dev/null
  [ "$?" -eq 0 ]
}

@test "nc to eBPF sk_lookup 6060" {
  nc -zv 127.0.0.1 6060 &> /dev/null
  [ "$?" -eq 0 ]
}

@test "nc to eBPF sk_lookup 7070" {
  nc -zv 127.0.0.1 7070 &> /dev/null
  [ "$?" -eq 0 ]
}

@test "nc to eBPF sk_lookup 8080" {
  nc -zv 127.0.0.1 8080 &> /dev/null
  [ "$?" -eq 0 ]
}
