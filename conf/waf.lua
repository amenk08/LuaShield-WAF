--[[
    LuaShield WAF 配置文件
    Configuration for LuaShield Web Application Firewall
]]

local _M = {
    -- 全局配置
    global = {
        waf_enable = true,
        mode = "block",        -- block | monitor | bypass
        debug = false,
        fail_open = true,      -- WAF 出错时是否放行
    },
    
    -- 模块开关
    modules = {
        ip_filter = {
            enable = true,
            whitelist_file = "conf/ip_whitelist.txt",
            blacklist_file = "conf/ip_blacklist.txt"
        },
        
        rate_limit = {
            enable = true,
            algorithm = "token_bucket",  -- token_bucket | sliding_window
            key_type = "ip",             -- ip | ip+uri | ip+user_agent
            
            thresholds = {
                -- Level 1: 软限制 - 封禁 1 分钟
                {
                    name = "soft_limit",
                    rate = 100,
                    burst = 200,
                    action = "ban",
                    ban_duration = 60,  -- 1分钟
                    ttl = 60
                },
                -- Level 2: 硬限制 - 封禁 5 分钟
                {
                    name = "hard_limit",
                    rate = 200,
                    burst = 300,
                    action = "ban",
                    ban_duration = 300,  -- 5分钟
                    ttl = 60
                },
                -- Level 3: 严重违规 - 封禁 1 小时
                {
                    name = "severe_limit",
                    rate = 500,
                    burst = 600,
                    action = "ban",
                    ban_duration = 3600,  -- 1小时
                    ttl = 60
                }
            },
            
            ban = {
                response_code = 403,
                response_body = "Your IP has been temporarily banned due to suspicious activity",
                show_remaining_time = true
            },
            
            whitelist = {
                ips = {"127.0.0.1"},
                uris = {
                    "/health", 
                    "/metrics",
                    "/static/",
                    "/assets/",
                    "/images/",
                    "/css/",
                    "/js/",
                    "/fonts/"
                },
                -- 静态资源文件扩展名
                extensions = {
                    "js", "css", "png", "jpg", "jpeg", "gif", "ico", 
                    "svg", "woff", "woff2", "ttf", "eot", "webp",
                    "mp4", "mp3", "pdf", "zip", "map"
                },
                user_agents = {}
            }
        },
        
        sql_injection = {
            enable = true,
            rule_file = "rules/sql_injection.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_cookie = true
        },
        
        xss = {
            enable = true,
            rule_file = "rules/xss.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_cookie = true
        },
        
        path_traversal = {
            enable = true,
            rule_file = "rules/path_traversal.json"
        },
        
        cmd_injection = {
            enable = true,
            rule_file = "rules/cmd_injection.json"
        },
        
        encoding_bypass = {
            enable = true,
            rule_file = "rules/encoding_bypass.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_headers = true,
            deep_decode = true  -- 深度解码检测隐藏攻击
        },
        
        cc_protection = {
            enable = true,
            threshold = 1000,
            time_window = 60
        }
    },
    
    -- 日志配置
    log = {
        enable = true,
        path = "/var/log/waf/",
        level = "info",
        format = "json"
    },
    
    -- 响应配置
    response = {
        block_code = 403,
        block_message = "Request blocked by LuaShield WAF",
        block_page = nil
    }
}

return _M
