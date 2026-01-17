local _M = {}
local block_page_template = [[
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access Denied - LuaShield WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 600px;
        }
        .shield {
            font-size: 80px;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(90deg, #ff6b6b, #feca57);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .message {
            font-size: 1.2rem;
            color: #a0a0a0;
            margin-bottom: 2rem;
            line-height: 1.6;
        }
        .details {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: left;
            font-family: monospace;
            font-size: 0.9rem;
            color: #888;
        }
        .details p { margin: 0.5rem 0; }
        .details span { color: #feca57; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Access Denied</h1>
        <p class="message">{{MESSAGE}}</p>
        <div class="details">
            <p><span>Request ID:</span> {{REQUEST_ID}}</p>
            <p><span>Time:</span> {{TIME}}</p>
            <p><span>Your IP:</span> {{CLIENT_IP}}</p>
        </div>
    </div>
</body>
</html>
]]
function _M.block(config, ctx)
    ctx = ctx or ngx.ctx.waf or {}
    
    local code = config.block_code or 403
    ngx.status = code
    

    if config.block_page then
        local f = io.open(config.block_page, "r")
        if f then
            local content = f:read("*all")
            f:close()
            ngx.header["Content-Type"] = "text/html; charset=utf-8"
            ngx.say(content)
            return ngx.exit(code)
        end
    end
    

    local page = block_page_template
    page = page:gsub("{{MESSAGE}}", config.block_message or "Your request has been blocked for security reasons.")
    page = page:gsub("{{REQUEST_ID}}", ctx.request_id or "N/A")
    page = page:gsub("{{TIME}}", ngx.localtime())
    page = page:gsub("{{CLIENT_IP}}", ctx.client_ip or ngx.var.remote_addr or "Unknown")
    
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(page)
    return ngx.exit(code)
end
function _M.json_error(code, message)
    local cjson = require "cjson.safe"
    ngx.status = code
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say(cjson.encode({
        error = true,
        code = code,
        message = message,
        request_id = ngx.ctx.waf and ngx.ctx.waf.request_id or nil,
        timestamp = ngx.localtime()
    }))
    return ngx.exit(code)
end
function _M.captcha_redirect(url, return_url)
    local redirect_url = url
    if return_url then
        redirect_url = redirect_url .. "?return_url=" .. ngx.escape_uri(return_url)
    end
    return ngx.redirect(redirect_url)
end

return _M
