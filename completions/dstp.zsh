#compdef dstp

local -a checks
checks=(ping dns configured_dns records tcp udp tls http https traceroute whois mtu)

_arguments -C \
  '(-a --addr)'{-a,--addr}'[target host]:host:' \
  '(-o --out)'{-o,--out}'[output format]:format:(plaintext json)' \
  '(-p)'{-p}'[ping count]:count:' \
  '(-t)'{-t}'[timeout seconds]:seconds:' \
  '--port[TLS/HTTPS port]:port:' \
  '--tcp-port[TCP port]:port:' \
  '--udp-port[UDP port]:port:' \
  '--http-port[HTTP port]:port:' \
  '--dns[custom DNS]:dns:' \
  '--doh[use DNS-over-HTTPS]' \
  '--doh-url[DoH URL]:url:' \
  '--doh-format[DoH format]:format:(rfc8484 json)' \
  '--doh-bootstrap[DoH bootstrap IP]:ip:' \
  '--method[HTTP method]:method:(GET HEAD)' \
  '--follow-redirects[follow redirects]' \
  '--insecure[skip TLS verify]' \
  '--extra[enable traceroute/whois/mtu]' \
  '--skip[skip checks (comma-separated)]:checks:_values -s , check $checks' \
  '--config[config file]:file:_files' \
  '(-q --quiet)'{-q,--quiet}'[quiet]' \
  '(-v --version)'{-v,--version}'[version]' \
  '(-h --help)'{-h,--help}'[help]' \
  '*:host:'
