# lua-cjwt

Lua bindings for [l8w8jwt](https://github.com/GlitchedPolygons/l8w8jwt).

## Installation

**1st step:** Clone the source code from [GitHub](https://github.com/ufownl/lua-cjwt.git): `git clone --recursive https://github.com/ufownl/lua-cjwt.git`

Make sure to do a recursive clone, otherwise you need to `git submodule update --init --recursive` at a later point!

**2nd step:** Build and install:

To build and install using the default settings, just enter the repository's directory and run the following commands:

```bash
mkdir build
cd build
cmake .. && make
sudo make install
```

## Usage

### Synopsis

```lua
-- Import the module
local cjwt = require("cjwt")

-- Encode
local rc, token = cjwt.encode({
  alg = "HS256"
}, {
  sub = "1234567890",
  name = "John Doe",
  iat = os.time(),
  foo = true,
  bar = false,
  pi = 3.14159
}, "foobar")
print("retcode: "..rc)
print("token: "..token)

-- Decode
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

-- No-validation Decode
local rc, _, claims = cjwt.decode(token)
print("retcode: "..rc)
print("claims:")
for k, v in pairs(claims) do
  print("\t"..k..": "..tostring(v))
end
```

### APIs for lua

#### cjwt.algs

**syntax:** `cjwt.algs.ALGORITHM_KEYWORD`

This table stores the IDs of the algorithms and is typically used to specify the verification method used for decoding.

The following code snippet prints all supported algorithms:

```lua
for k, _ in pairs(require("cjwt").algs) do
  print(k)
end
```

#### cjwt.encode

**syntax:** `<number>retcode, <string>token = cjwt.encode(<table>header, <table>payload, <string>secret_key[, <string>secret_key_password])`

Create, sign and encode a JSON-Web-Token.

A successful call returns 0 and a string representing the encoded JSON-Web-Token. Otherwise, it returns a specific `retcode` and `nil`. See [here](https://github.com/GlitchedPolygons/l8w8jwt/blob/b24083d920c93a2f46f30d3d3d7a2663ac19ca09/include/l8w8jwt/retcodes.h#L33) for definitions of retcodes.

#### cjwt.decode

**syntax:** `<number>retcode, <number>validation_result, <table>claims = cjwt.decode(<string>token[, <number>alg, <string>verification_key[, <table>validation]])`

Decode and validate a JSON-Web-Token.

A successful call returns 0, a number representing the validation result and a table containing all claims. Otherwise, it returns a specific `retcode` and 2 `nil`. This `retcode` is the same as `cjwt.encode` and see [here](https://github.com/GlitchedPolygons/l8w8jwt/blob/b24083d920c93a2f46f30d3d3d7a2663ac19ca09/include/l8w8jwt/decode.h#L45) for definitions of validation result.

Available validations:

```lua
{
  iss = "Verify issuer claim",
  sub = "Verify subject claim",
  aud = "Verify audience claim",
  jti = "Verify JWT ID claim",
  exp = true,  -- Verify expiration time claim
  exp_tolerance = 60,
  nbf = true,  -- Verify not before claim
  nbf_tolerance = 60,
  iat = true,  -- Verify issued at claim
  iat_tolerance = 60,
  typ = "JWT"
}
```

### Supported Claim Types

- [x] String
- [x] Integer
- [x] Number
- [x] Boolean
- [ ] Null
- [ ] Array
- [ ] Object
