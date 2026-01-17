local _M = {
    name = "path_traversal",
    version = "0.1.0"
}

local loader = require "resty.waf.rules.loader"
local matcher = require "resty.waf.rules.matcher"

local rules = {}
local default_patterns = {
    {
        id = "pt-001",
        name = "Directory Traversal",
        pattern = "(?:\\.\\./|\\.\\.\\\\)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "pt-002",
        name = "Encoded Traversal",
        pattern = "(?:%2e%2e[%2f%5c]|%2e%2e/|\\.\\.%2f|%2e%2e\\\\|\\.\\.%5c)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "pt-003",
        name = "Double Encoded",
        pattern = "(?:%252e%252e%252f|%252e%252e%255c)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "pt-004",
        name = "Sensitive Files",
        pattern = "(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|/windows/system32|boot\\.ini|win\\.ini)",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "pt-005",
        name = "Config Files",
        pattern = "(?i)(?:\\.htaccess|\\.htpasswd|\\.env|config\\.php|wp-config\\.php|web\\.config)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "pt-006",
        name = "Git/SVN Directories",
        pattern = "(?i)(?:/\\.git/|/\\.svn/|/\\.hg/|\\.git/config)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "pt-007",
        name = "Backup Files",
        pattern = "(?i)(?:\\.bak$|\\.old$|\\.backup$|~$|\\.swp$|\\.orig$)",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },
    {
        id = "pt-008",
        name = "Log Files",
        pattern = "(?i)(?:/var/log/|access\\.log|error\\.log|debug\\.log)",
        operator = "regex",
        enabled = true,
        severity = "medium"
    }
}
function _M.init(config, global_config)
    if config.rule_file then
        local loaded, err = loader.load_file(config.rule_file)
        if loaded then
            rules = loader.compile_rules(loaded)
            ngx.log(ngx.INFO, "Path Traversal: loaded ", #rules, " rules from file")
        else
            ngx.log(ngx.WARN, "Path Traversal: using default rules, file error: ", err)
            rules = loader.compile_rules(default_patterns)
        end
    else
        rules = loader.compile_rules(default_patterns)
        ngx.log(ngx.INFO, "Path Traversal: using ", #rules, " default rules")
    end
end
function _M.check(ctx, config)
    local targets = {}
    

    table.insert(targets, ctx.uri)
    table.insert(targets, ctx.request_uri)
    

    for k, v in pairs(ctx.uri_args or {}) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                table.insert(targets, item)
            end
        else
            table.insert(targets, v)
        end
    end
    

    if ctx.body then
        table.insert(targets, ctx.body)
    end
    
    local result = matcher.match_any(rules, targets)
    
    if result.matched then
        return {
            blocked = true,
            attack_type = "Path Traversal",
            rule_id = result.rule.id,
            evidence = result.evidence,
            severity = result.rule.severity
        }
    end
    
    return { blocked = false }
end

return _M
