local _M = {}

local bit = require "bit"
function _M.ip_to_number(ip)
    if not ip or type(ip) ~= "string" then
        return nil
    end
    
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil
    end
    
    return a * 16777216 + b * 65536 + c * 256 + d
end
function _M.number_to_ip(num)
    if not num or type(num) ~= "number" then
        return nil
    end
    
    local d = num % 256
    num = math.floor(num / 256)
    local c = num % 256
    num = math.floor(num / 256)
    local b = num % 256
    num = math.floor(num / 256)
    local a = num % 256
    
    return string.format("%d.%d.%d.%d", a, b, c, d)
end
function _M.parse_cidr(cidr)
    local ip, mask = cidr:match("^([%d%.]+)/(%d+)$")
    
    if ip and mask then
        mask = tonumber(mask)
        if mask < 0 or mask > 32 then
            return nil, nil
        end
    else

        ip = cidr
        mask = 32
    end
    
    local ip_num = _M.ip_to_number(ip)
    if not ip_num then
        return nil, nil
    end
    
    return ip_num, mask
end
function _M.match_cidr(ip, cidr)
    local ip_num = _M.ip_to_number(ip)
    if not ip_num then
        return false
    end
    
    local cidr_ip, mask = _M.parse_cidr(cidr)
    if not cidr_ip then
        return false
    end
    
    if mask == 32 then
        return ip_num == cidr_ip
    end
    

    local network_mask = bit.lshift(0xFFFFFFFF, 32 - mask)
    

    return bit.band(ip_num, network_mask) == bit.band(cidr_ip, network_mask)
end
function _M.in_cidrs(ip, cidrs)
    for _, cidr in ipairs(cidrs) do
        if _M.match_cidr(ip, cidr) then
            return true
        end
    end
    return false
end
function _M.is_private(ip)
    local private_ranges = {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    }
    return _M.in_cidrs(ip, private_ranges)
end

return _M
