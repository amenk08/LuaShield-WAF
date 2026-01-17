local _M = {}

local cjson = require "cjson.safe"
local function get_client_ip()
    local ip = nil
    

    local xff = ngx.req.get_headers()["X-Forwarded-For"]
    if xff then

        ip = xff:match("([%d%.]+)")
    end
    

    if not ip then
        ip = ngx.req.get_headers()["X-Real-IP"]
    end
    

    if not ip then
        ip = ngx.var.remote_addr
    end
    
    return ip or "0.0.0.0"
end
local function parse_cookies()
    local cookie_header = ngx.req.get_headers()["Cookie"]
    local cookies = {}
    
    if cookie_header then
        for k, v in cookie_header:gmatch("([^;%s]+)=([^;]+)") do
            cookies[k] = v
        end
    end
    
    return cookies
end
local function get_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    

    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "r")
            if f then
                body = f:read("*all")
                f:close()
            end
        end
    end
    
    return body
end
local function get_post_args()
    local content_type = ngx.req.get_headers()["Content-Type"] or ""
    local post_args = {}
    
    if content_type:find("application/x-www-form-urlencoded", 1, true) then
        local args, err = ngx.req.get_post_args()
        if args then
            post_args = args
        end
    elseif content_type:find("application/json", 1, true) then
        local body = get_body()
        if body then
            local data = cjson.decode(body)
            if data and type(data) == "table" then
                post_args = data
            end
        end
    end
    
    return post_args
end
function _M.build_context()
    local ctx = {

        client_ip = get_client_ip(),
        method = ngx.req.get_method(),
        uri = ngx.var.uri,
        request_uri = ngx.var.request_uri,
        host = ngx.var.host,
        user_agent = ngx.req.get_headers()["User-Agent"] or "",
        referer = ngx.req.get_headers()["Referer"] or "",
        content_type = ngx.req.get_headers()["Content-Type"] or "",
        

        uri_args = ngx.req.get_uri_args() or {},
        post_args = {},
        headers = ngx.req.get_headers() or {},
        cookies = parse_cookies(),
        body = nil,
        

        is_attack = false,
        attack_type = nil,
        attack_score = 0,
        matched_rules = {},
        rule_id = nil,
        evidence = nil,
        action = nil,
        

        start_time = ngx.now(),
        request_id = ngx.var.request_id or ngx.md5(ngx.now() .. ngx.worker.pid())
    }
    

    if ctx.method == "POST" or ctx.method == "PUT" or ctx.method == "PATCH" then
        ctx.body = get_body()
        ctx.post_args = get_post_args()
    end
    
    return ctx
end
function _M.get_all_values(ctx)
    local values = {}
    

    table.insert(values, ctx.uri)
    table.insert(values, ctx.request_uri)
    

    for k, v in pairs(ctx.uri_args) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                table.insert(values, item)
            end
        else
            table.insert(values, v)
        end
    end
    

    for k, v in pairs(ctx.post_args) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                table.insert(values, item)
            end
        else
            table.insert(values, tostring(v))
        end
    end
    

    if ctx.body then
        table.insert(values, ctx.body)
    end
    

    for k, v in pairs(ctx.cookies) do
        table.insert(values, v)
    end
    
    return values
end

return _M
