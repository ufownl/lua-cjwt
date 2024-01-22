local rc, token = require("cjwt").encode({
  alg = "HS256"
}, {
  sub = "1234567890",
  name = "John Doe",
  iat = os.time()
}, "foobar")
print("retcode: "..rc)
print("token: "..token)
