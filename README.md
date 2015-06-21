# cerber
Simple authentification server

Initially built to handle docker distribution token authentification, not sure if it will be maintained in any way, it was a simple and toy project to get some experience with golang.

# zone
Zone is a area for authentification, just like a VirtualHost, here is simple yml zone:
```
# service, that name should be same as in distribution configuration
name: docker-distribution
description: xphoenix.org private docker registry

# How password are hashed (if it hashed)
hashing: md5

# Right now only RS256 supported, cert/key required
sign:
  method: RS256
  cert:
    key: /etc/zones/distribution.key
    crt: /etc/zones/distribution.crt

# Group defines set of action allowed
groups: 
- name: write
  actions:
  - xphoenix/cerber:push
  - xphoenix/distribution:push
  - xphoenix/mongo:push
  - xphoenix/vulcand:push
  - crafthands/web:push
- name: read
  actions:
  - xphoenix/cerber:pull
  - xphoenix/distribution:pull
  - xphoenix/mongo:pull
  - xphoenix/vulcand:pull

# Users with groups assigned
users:
- name: admin
  passwd: 21232f297a57a5a743894a0e4a801fc3
  groups: [read,write]
- name: deployer
  passwd: b5f6e212492dd8ead88f44201ab105d7
  groups: [read]
```

#todo
- none hasher (trivial)
- refactor actions to be in form <type>:<name>:<action>
- refresh token implementation
- decode token implementation (testing...)
- tests
- Zone must be interface
- MongoDB implementation
- Inotify for directory implementation
- Zone/Users/Groups cache
