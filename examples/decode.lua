local cjwt = require("cjwt")
local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDU5OTAxNjYsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJmb28iOnRydWUsImJhciI6ZmFsc2UsInBpIjozLjE0MTU5MjY1MzUsInRlc3QiOm51bGx9.ap5iad4-UsU33yG0yEEb1EoOKvmLta2B62dBo2E8wH0"
local rc, vc, claims = cjwt.decode(token, cjwt.algs.HS256, "foobar", {
  sub = "1234567890",
  iat = true,
  typ = "JWT"
})
print("retcode: "..rc)
print("valcode: "..vc)
print("claims:")
for k, v in pairs(claims) do
  print("\t"..k..": "..tostring(v))
end
