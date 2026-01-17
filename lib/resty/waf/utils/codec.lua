local _M = {}
function _M.url_decode(str)
    if not str then return nil end
    
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    
    return str
end
function _M.url_decode_double(str)
    if not str then return nil end
    

    local decoded = _M.url_decode(str)

    decoded = _M.url_decode(decoded)
    
    return decoded
end
function _M.unicode_decode(str)
    if not str then return nil end
    
    str = str:gsub("%%u(%x%x%x%x)", function(h)
        local code = tonumber(h, 16)
        if code < 128 then
            return string.char(code)
        end
        return ""
    end)
    
    return str
end
function _M.html_decode(str)
    if not str then return nil end
    
    local entities = {
        ["&lt;"] = "<",
        ["&gt;"] = ">",
        ["&amp;"] = "&",
        ["&quot;"] = '"',
        ["&apos;"] = "'",
        ["&#39;"] = "'",
        ["&nbsp;"] = " "
    }
    
    for entity, char in pairs(entities) do
        str = str:gsub(entity, char)
    end
    

    str = str:gsub("&#(%d+);", function(d)
        local code = tonumber(d)
        if code and code < 256 then
            return string.char(code)
        end
        return ""
    end)
    
    str = str:gsub("&#x(%x+);", function(h)
        local code = tonumber(h, 16)
        if code and code < 256 then
            return string.char(code)
        end
        return ""
    end)
    
    return str
end
function _M.hex_decode(str)
    if not str then return nil end
    
    str = str:gsub("\\x(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    
    str = str:gsub("0x(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    
    return str
end
function _M.decode_all(str)
    if not str then return nil end
    
    local decoded = str
    

    decoded = _M.url_decode(decoded)
    decoded = _M.unicode_decode(decoded)
    decoded = _M.html_decode(decoded)
    decoded = _M.hex_decode(decoded)
    
    return decoded
end
function _M.has_encoding(str)
    if not str then return false end
    

    if str:match("%%[0-9a-fA-F][0-9a-fA-F]") then
        return true, "url_encoding"
    end
    

    if str:match("%%25[0-9a-fA-F][0-9a-fA-F]") then
        return true, "double_url_encoding"
    end
    

    if str:match("%%u[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]") then
        return true, "unicode_encoding"
    end
    

    if str:match("&%w+;") or str:match("&#%d+;") or str:match("&#x%x+;") then
        return true, "html_entity"
    end
    

    if str:match("\\x%x%x") or str:match("0x%x%x") then
        return true, "hex_encoding"
    end
    
    return false, nil
end
function _M.normalize(str)
    if not str then return nil end
    
    local normalized = str:lower()
    normalized = _M.decode_all(normalized)
    
    return normalized
end

return _M
