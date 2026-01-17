local _M = {}
local function match_rule(rule, target)
    if not rule.enabled then
        return nil
    end
    
    local matched = nil
    
    if rule.operator == "regex" then
        if rule.compiled then
            matched = ngx.re.match(target, rule.compiled)
        else

            local ok, res = pcall(function()
                return ngx.re.match(target, rule.pattern, "joi")
            end)
            if ok then
                matched = res
            end
        end
    elseif rule.operator == "contains" then
        if target:find(rule.pattern, 1, true) then
            matched = { [0] = rule.pattern }
        end
    elseif rule.operator == "equals" then
        if target == rule.pattern then
            matched = { [0] = target }
        end
    elseif rule.operator == "startswith" then
        if target:sub(1, #rule.pattern) == rule.pattern then
            matched = { [0] = rule.pattern }
        end
    elseif rule.operator == "endswith" then
        if target:sub(-#rule.pattern) == rule.pattern then
            matched = { [0] = rule.pattern }
        end
    end
    
    return matched
end
function _M.match(rules, target)
    if not target or target == "" then
        return { matched = false }
    end
    
    for _, rule in ipairs(rules) do
        local matched = match_rule(rule, target)
        if matched then
            return {
                matched = true,
                rule = rule,
                evidence = matched[0] or target:sub(1, 100)
            }
        end
    end
    
    return { matched = false }
end
function _M.match_any(rules, targets)
    for _, target in ipairs(targets) do
        if target and target ~= "" then
            local result = _M.match(rules, target)
            if result.matched then
                return result
            end
        end
    end
    return { matched = false }
end

return _M
