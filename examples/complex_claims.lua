local cjwt = require("cjwt")
print(cjwt.array({1, 3.14, "foobar", true, false, cjwt.null(), cjwt.object({
  nested_foo = "nested hello",
  nested_bar = "nested world",
  nested_true = true,
  nested_false = false,
  nested_null = cjwt.null(),
  nested_int = 5,
  nested_num = 6.28
}), cjwt.array({"aaa", 2, 6.28, cjwt.null(), false, true})}))
print(cjwt.object({
  foo = "hello",
  bar = "world",
  ["true"] = true,
  ["false"] = false,
  int = 666,
  num = 0.14,
  null = cjwt.null(),
  nested_object = cjwt.object({
    nested_foo = "nested hello",
    nested_bar = "nested world",
    nested_true = true,
    nested_false = false,
    nested_null = cjwt.null(),
    nested_int = 5,
    nested_num = 6.28
  }),
  nested_arr = cjwt.array({"aaa", 2, 6.28, cjwt.null(), false, true})
}))
