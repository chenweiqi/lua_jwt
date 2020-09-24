# lua_jwt
Lua jwt - a jwt library for Lua

## Build
make sure lua was installed in your linux, and the following command 'make install' is just match lua 5.3, so lua 5.3 is suggested.
```plain
$ make all
$ make install
```

the command 'make install' is short for the following commands: 
```plain
$ cp cutil.so /usr/local/lib/lua/5.3
$ chmod 755 /usr/local/lib/lua/5.3/cutil.so
```



## Test
there is an example in the 'tests' dir.
```plain
$ /usr/local/bin/lua
Lua 5.3.2  Copyright (C) 1994-2015 Lua.org, PUC-Rio
> dofile("tests/sample.lua")
eyJhbGciOiJFUzI1NiIsImtpZCI6ImFiY2RlZmciLCJ0eXAiOiJKV1QifQ.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.ZyAoSY4japHsFozjD3hR-iSVJZj4THgsZc3t2NqCqznUhRg9ell8ZwmjGRzyN2B--t7kIIHy0IsSmY5NFutrqQ
{"alg":"ES256","kid":"abcdefg","typ":"JWT"}.{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}
{"alg":"none","kid":"abcdefg","typ":"JWT"}.{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiGaLqP6y+SJCCBq5Hv6p
GDbG/SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInq
UvjJur++hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPyg
jLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk+ILjv1bORSRl
8AK677+1T8isGfHKXGZ/ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl
4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw+zHL
wQIDAQAB
-----END PUBLIC KEY-----

{"alg":"RS256","kid":"86D88Kf","typ":"JWT"}.{"aud":"com.xxx.xxx","auth_time":1589184685,"c_hash":"7X3slvtuASI0baRmM0TakA","email":"aq32k2vzcw@privaterelay.appleid.com","email_verified":"true","exp":1589185285,"iat":1589184685,"is_private_email":"true","iss":"https://appleid.apple.com","nonce_supported":true,"sub":"001940.7a1141aa001c469ea1563c6bae99c37d.0307"}
{"alg":"none","kid":"86D88Kf"}.{"aud":"com.xxx.xxx","auth_time":1589184685,"c_hash":"7X3slvtuASI0baRmM0TakA","email":"aq32k2vzcw@privaterelay.appleid.com","email_verified":"true","exp":1589185285,"iat":1589184685,"is_private_email":"true","iss":"https://appleid.apple.com","nonce_supported":true,"sub":"001940.7a1141aa001c469ea1563c6bae99c37d.0307"}
```
