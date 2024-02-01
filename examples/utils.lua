local _M = {}

function _M.dump_table(t, prefix)
  if not prefix then
    prefix = ""
  end
  for k, v in pairs(t) do
    if type(v) == "table" then
      print(prefix..k..":")
      _M.dump_table(v, prefix.."\t")
    else
      print(prefix..k..": "..tostring(v))
    end
  end
end

return _M
