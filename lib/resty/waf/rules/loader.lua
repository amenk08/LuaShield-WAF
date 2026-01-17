local _M = {}

local cjson = require "cjson.safe"
function _M.load_file(filepath)
    local file = io.open(filepath, "r")
    if not file then
        return nil, "Cannot open file: " .. filepath
    end
    
    local content = file:read("*all")
    file:close()
    
    if not content or content == "" then
        return nil, "Empty file: " .. filepath
    end
    
    local data, err = cjson.decode(content)
    if not data then
        return nil, "JSON parse error: " .. (err or "unknown")
    end
    
    return data.rules or data
end
function _M.compile_rules(rules)
    for _, rule in ipairs(rules) do
        if rule.pattern and rule.operator == "regex" and rule.enabled ~= false then

            local ok, compiled_or_err, err = pcall(function()
                return ngx.re.compile(rule.pattern, "joi")
            end)
            
            if ok and compiled_or_err then
                rule.compiled = compiled_or_err
            else

                local error_msg = ok and err or compiled_or_err
                ngx.log(ngx.WARN, "[WAF] Failed to compile rule ", rule.id or "unknown", 
                    " (", rule.name or "", "): ", error_msg or "unknown error",
                    " | Pattern: ", (rule.pattern or ""):sub(1, 100))
                rule.enabled = false
                rule.compile_error = error_msg
            end
        end
    end
    return rules
end

return _M
