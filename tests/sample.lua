
local function run_test(run_times, func)
	collectgarbage()
	local cnt = collectgarbage("count")
	local now = os.time()
	for k =1, run_times do
		func()
	end
	collectgarbage()
	local cnt1 = collectgarbage("count")
	local now1 = os.time()
	print("mem diff", cnt1 - cnt)
	print("time diff", now1 - now)
	print("average rate", string.format("%.6f", (now1 - now) / run_times))
end


local pub_pem = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
]]

local pri_pem = [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----
]]

local header = {
	kid = "abcdefg",
}
local token = {
	sub = "1234567890",
	name = "John Doe",
	admin = true,
	iat = 1516239022,
}

local modulus = "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ"
local exponent = "AQAB"


local jwt = require "jwt"
local ok, jwt_str = jwt.jwt_encode(header, token, pri_pem, 'es256')
print(">> jwt.jwt_encode(header, token, pri_pem, 'es256')")
print(jwt_str)

local ok, token_str = jwt.jwt_decode(jwt_str, pub_pem)
print(">> jwt.jwt_decode(jwt_str, pub_pem)")
print(token_str)


local ok, token_str = jwt.jwt_decode(jwt_str)
print(">> jwt.jwt_decode(jwt_str)")
print(token_str)

local ok, pem = jwt.jwk_to_pem(modulus, exponent)
print(">> jwt.jwk_to_pem(modulus, exponent)")
print(pem)


local jwt_str = "eyJraWQiOiI4NkQ4OEtmIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmNoYW5nZGFvLnR0c2Nob29sIiwiZXhwIjoxNTg5MTg1Mjg1LCJpYXQiOjE1ODkxODQ2ODUsInN1YiI6IjAwMTk0MC43YTExNDFhYTAwMWM0NjllYTE1NjNjNmJhZTk5YzM3ZC4wMzA3IiwiY19oYXNoIjoiN1gzc2x2dHVBU0kwYmFSbU0wVGFrQSIsImVtYWlsIjoiYXEzMmsydnpjd0Bwcml2YXRlcmVsYXkuYXBwbGVpZC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJpc19wcml2YXRlX2VtYWlsIjoidHJ1ZSIsImF1dGhfdGltZSI6MTU4OTE4NDY4NSwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlfQ.S9wCOt6EeOoRrSMq4kUkPgJPyP1ruMXEcEZeeQEd1CDpcyVWLI8nTOqrl-l0sWYR-5nl2-1iJyiu77fRv8T7dBoV0EHT7GgM1l7qhnWsI9I8V-56rA9ArdJrLIBJbxu7j-xzQhZb6PZ5MSxPZ6WqZay0RpP9JiQ23ybssWQsMnqzvVZkye0iNtBGT1LnfT80XNxmj8L2uJZY08mXjjWWsYY_h0_IRvqOLyaW99w-F8T9KuDkWz2Z-DJX_tiKC0DOT03ypBv82H0v_v-8lFlp4rNRSB82CdgfYwEWElU7zKZfaHJOxT3wOvRXNpbj6_hENPdbtG2ozgdg2oVEiamz0g"
local ok, token_str = jwt.jwt_decode(jwt_str, pem)
print(">> jwt.jwt_decode(jwt_str, pem)")
print(token_str)

local ok, token_str = jwt.jwt_decode(jwt_str)
print(">> jwt.jwt_decode(jwt_str)")
print(token_str)


-- local function test()
-- 	jwt.jwt_encode(header, token, pri_pem, 'es256')
-- 	jwt.jwt_encode(header, token, pri_pem, '')
-- 	jwt.jwt_encode(header, token, '', '')
-- 	jwt.jwt_decode(jwt_str, pem)
-- 	jwt.jwt_decode(jwt_str)
-- 	jwt.jwk_to_pem(modulus, exponent)
-- 	jwt.jwk_to_pem("", "")
-- end

-- print("----------------")
-- print("--- run test ---")
-- print("----------------")
-- run_test(500000, test)