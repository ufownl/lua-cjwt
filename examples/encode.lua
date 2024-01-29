local cjwt = require("cjwt")
local rc, token = cjwt.encode({
  alg = "HS256"
}, {
  sub = "1234567890",
  name = "John Doe",
  iat = os.time(),
  test = cjwt.null()
}, "foobar")
print("retcode: "..rc)
print("token: "..token)
