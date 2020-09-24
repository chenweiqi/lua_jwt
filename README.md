# lua_jwt
Lua jwt - a jwt library for Lua

## Build
make sure lua was installed in your linux, and the following command 'make test' is just match lua 5.3, so lua 5.3 is suggested.
```plain
$ make
$ make test
```

## Depends
- OpenSSL
- https://github.com/akheron/jansson
- https://github.com/benmcollins/libjwt


## Test
there is an example in the 'tests' dir.
```plain
>> jwt.jwt_encode(header, token, pri_pem, 'es256')
eyJhbGciOiJFUzI1NiIsImtpZCI6ImFiY2RlZmciLCJ0eXAiOiJKV1QifQ.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.QDzbIkVpLZ1Uf6OwnrabKnz9xH3WJ_nLoiUZlT37IiVu3aXEMCfZkE3LlDUo14JUE6iBHo1B_jG91zwZOz7oZA
>> jwt.jwt_decode(jwt_str, pub_pem)
{"alg":"ES256","kid":"abcdefg","typ":"JWT"}.{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}
>> jwt.jwt_decode(jwt_str)
{"alg":"none","kid":"abcdefg","typ":"JWT"}.{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}
>> jwt.jwk_to_pem(modulus, exponent)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiGaLqP6y+SJCCBq5Hv6p
GDbG/SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInq
UvjJur++hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPyg
jLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk+ILjv1bORSRl
8AK677+1T8isGfHKXGZ/ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl
4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw+zHL
wQIDAQAB
-----END PUBLIC KEY-----

>> jwt.jwt_decode(jwt_str, pem)
{"alg":"RS256","kid":"86D88Kf","typ":"JWT"}.{"aud":"com.changdao.ttschool","auth_time":1589184685,"c_hash":"7X3slvtuASI0baRmM0TakA","email":"aq32k2vzcw@privaterelay.appleid.com","email_verified":"true","exp":1589185285,"iat":1589184685,"is_private_email":"true","iss":"https://appleid.apple.com","nonce_supported":true,"sub":"001940.7a1141aa001c469ea1563c6bae99c37d.0307"}
>> jwt.jwt_decode(jwt_str)
{"alg":"none","kid":"86D88Kf"}.{"aud":"com.changdao.ttschool","auth_time":1589184685,"c_hash":"7X3slvtuASI0baRmM0TakA","email":"aq32k2vzcw@privaterelay.appleid.com","email_verified":"true","exp":1589185285,"iat":1589184685,"is_private_email":"true","iss":"https://appleid.apple.com","nonce_supported":true,"sub":"001940.7a1141aa001c469ea1563c6bae99c37d.0307"}
```
