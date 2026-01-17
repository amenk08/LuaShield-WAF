<div align="center">

# 🛡️ LuaShield WAF

**高性能 Web 应用防火墙 | High-Performance Web Application Firewall**

基于 OpenResty/Nginx 的下一代 WAF，使用纯 Lua 实现

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenResty](https://img.shields.io/badge/OpenResty-1.27%2B-green.svg)](https://openresty.org/)
[![Lua](https://img.shields.io/badge/Lua-5.1%2B-blue.svg)](https://www.lua.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-orange.svg)](https://ubuntu.com/)

[English](#features) | [中文文档](#功能特性)

</div>

---

## ✨ 功能特性

| 模块 | 描述 | 状态 |
|------|------|:----:|
| 🔒 **SQL 注入防护** | 检测 UNION、盲注、堆叠查询、时间盲注等 | ✅ |
| 🛡️ **XSS 防护** | 检测脚本注入、事件处理器、协议注入等 | ✅ |
| 💻 **命令注入防护** | 检测 Shell 命令、反向 Shell、权限提升等 | ✅ |
| 📁 **路径遍历防护** | 阻止目录穿越和敏感文件访问 | ✅ |
| 🔐 **编码绕过检测** | 检测多重编码、Unicode、UTF-7 等绕过手法 | ✅ |
| ⚡ **智能限流** | 令牌桶算法，多级阈值，自动封禁 | ✅ |
| 📋 **IP 黑白名单** | 支持 CIDR 格式 | ✅ |
| 📊 **攻击日志** | JSON 格式按天分割，支持 ELK 集成 | ✅ |

---

## 🚀 快速开始

### 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| 操作系统 | Ubuntu 24.04 / CentOS 7+ | 推荐 Ubuntu 24.04 |
| OpenResty | >= 1.27.1.2 | 推荐最新版本 |
| LuaJIT | >= 2.1 | OpenResty 内置 |

### 安装 OpenResty (Ubuntu 24.04)

```bash
# 1. 安装依赖
sudo apt-get update
sudo apt-get install -y wget gnupg ca-certificates

# 2. 添加 OpenResty 官方源
wget -O - https://openresty.org/package/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/ubuntu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/openresty.list > /dev/null

# 3. 安装 OpenResty
sudo apt-get update
sudo apt-get install -y openresty

# 4. 验证安装
openresty -v
# 输出: nginx version: openresty/1.27.1.2
```

### 安装 LuaShield WAF

```bash
# 1. 克隆项目到 OpenResty 配置目录
sudo git clone https://github.com/zy2006cs/LuaShield-WAF.git /etc/openresty/openresty-waf

# 2. 创建日志目录
sudo mkdir -p /var/log/waf
sudo chown www-data:www-data /var/log/waf

# 3. 设置权限
sudo chown -R root:root /etc/openresty/openresty-waf
sudo chmod -R 755 /etc/openresty/openresty-waf
```

---

## ⚙️ Nginx 配置 (详细生产配置)

### 1. 主配置文件 nginx.conf

编辑 `/etc/openresty/nginx/conf/nginx.conf`：

```nginx
worker_processes auto;
error_log /var/log/openresty/error.log warn;
pid /run/openresty.pid;

events {
    worker_connections 10240;
    use epoll;
    multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/openresty/access.log main;
    
    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout 65;
    
    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    
    # ========================================
    # LuaShield WAF 配置 - 必须放在 http 块内
    # ========================================
    
    # 共享内存配置 (根据服务器内存调整)
    lua_shared_dict waf_config    1m;    # 配置缓存
    lua_shared_dict waf_rules    10m;    # 规则缓存
    lua_shared_dict waf_limit    20m;    # 限流计数器
    lua_shared_dict waf_ban      10m;    # 封禁列表
    lua_shared_dict waf_ip_cache  5m;    # IP 缓存
    lua_shared_dict waf_stats     2m;    # 统计数据
    
    # Lua 模块搜索路径
    lua_package_path "/etc/openresty/openresty-waf/lib/?.lua;/etc/openresty/openresty-waf/lib/?/init.lua;;";
    
    # 主进程初始化 WAF
    init_by_lua_block {
        local waf = require "resty.waf"
        waf.init("/etc/openresty/openresty-waf/conf/waf.lua")
    }
    
    # Worker 进程初始化
    init_worker_by_lua_block {
        local waf = require "resty.waf"
        waf.init_worker()
    }
    
    # 引入站点配置
    include /etc/openresty/nginx/conf/conf.d/*.conf;
}
```

### 2. 站点配置文件

创建 `/etc/openresty/nginx/conf/conf.d/your-site.conf`：

```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    
    # ========================================
    # LuaShield WAF 启用 - 放在 server 块内
    # ========================================
    
    # WAF 检测 (请求处理阶段)
    access_by_lua_block {
        local waf = require "resty.waf"
        waf.exec()
    }
    
    # WAF 日志 (日志阶段)
    log_by_lua_block {
        local waf = require "resty.waf"
        waf.log()
    }
    
    # ========================================
    # 其他站点配置
    # ========================================
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # 静态资源 (可选：静态资源不经过 WAF)
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        root /var/www/html;
        expires 30d;
        add_header Cache-Control "public, immutable";
        
        # 静态资源不启用 WAF，提高性能
        access_by_lua_block { }
    }
    
    # 健康检查接口 (跳过 WAF)
    location = /health {
        access_by_lua_block { }
        return 200 "OK";
    }
}

# HTTPS 配置
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    
    ssl_certificate     /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    
    # WAF 检测
    access_by_lua_block {
        local waf = require "resty.waf"
        waf.exec()
    }
    
    log_by_lua_block {
        local waf = require "resty.waf"
        waf.log()
    }
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. 验证并重载配置

```bash
# 测试配置语法
sudo openresty -t

# 输出应该为:
# nginx: the configuration file /etc/openresty/nginx/conf/nginx.conf syntax is ok
# nginx: configuration file /etc/openresty/nginx/conf/nginx.conf test is successful

# 重载配置
sudo openresty -s reload

# 或者重启服务
sudo systemctl restart openresty
```

---

## 📋 WAF 配置文件

主配置文件: `/etc/openresty/openresty-waf/conf/waf.lua`

### 完整配置示例

```lua
--[[
    LuaShield WAF 配置文件
]]

local _M = {
    -- 全局配置
    global = {
        waf_enable = true,      -- WAF 总开关
        mode = "block",         -- block | monitor | bypass
        debug = false,          -- 调试模式
        fail_open = true        -- WAF 出错时是否放行
    },
    
    -- 模块配置
    modules = {
        -- IP 过滤
        ip_filter = {
            enable = true,
            whitelist_file = "conf/ip_whitelist.txt",
            blacklist_file = "conf/ip_blacklist.txt"
        },
        
        -- 限流配置
        rate_limit = {
            enable = true,
            algorithm = "token_bucket",  -- 令牌桶算法
            key_type = "ip",             -- 按 IP 限流
            
            thresholds = {
                -- Level 1: 软限制
                {
                    name = "soft_limit",
                    rate = 100,          -- 每分钟 100 请求
                    burst = 200,         -- 突发容量 200
                    action = "ban",
                    ban_duration = 60,   -- 封禁 1 分钟
                    ttl = 60
                },
                -- Level 2: 硬限制
                {
                    name = "hard_limit",
                    rate = 200,
                    burst = 300,
                    action = "ban",
                    ban_duration = 300,  -- 封禁 5 分钟
                    ttl = 60
                },
                -- Level 3: 严重违规
                {
                    name = "severe_limit",
                    rate = 500,
                    burst = 600,
                    action = "ban",
                    ban_duration = 3600, -- 封禁 1 小时
                    ttl = 60
                }
            },
            
            ban = {
                response_code = 403,
                response_body = "Your IP has been temporarily banned",
                show_remaining_time = true
            },
            
            whitelist = {
                ips = {"127.0.0.1", "10.0.0.0/8"},
                uris = {"/health", "/metrics", "/static/", "/assets/"},
                extensions = {
                    "js", "css", "png", "jpg", "jpeg", "gif", "ico",
                    "svg", "woff", "woff2", "ttf", "eot", "webp",
                    "mp4", "mp3", "pdf", "zip", "map"
                },
                user_agents = {}
            }
        },
        
        -- SQL 注入检测
        sql_injection = {
            enable = true,
            rule_file = "rules/sql_injection.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_cookie = true
        },
        
        -- XSS 检测
        xss = {
            enable = true,
            rule_file = "rules/xss.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_cookie = true
        },
        
        -- 路径遍历检测
        path_traversal = {
            enable = true,
            rule_file = "rules/path_traversal.json"
        },
        
        -- 命令注入检测
        cmd_injection = {
            enable = true,
            rule_file = "rules/cmd_injection.json"
        },
        
        -- 编码绕过检测
        encoding_bypass = {
            enable = true,
            rule_file = "rules/encoding_bypass.json",
            check_uri = true,
            check_args = true,
            check_body = true,
            check_headers = true,
            deep_decode = true
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
```

### 运行模式说明

| 模式 | 说明 | 使用场景 |
|------|------|---------|
| `block` | 检测并拦截攻击 | 生产环境 |
| `monitor` | 仅记录不拦截 | 测试阶段，观察误报 |
| `bypass` | 完全跳过 WAF | 紧急情况临时关闭 |

---

## 🧪 测试防护效果

### 使用 curl 测试

```bash
# SQL 注入测试
curl "http://your-domain.com/?id=1' OR '1'='1"
# 预期: 403 Forbidden

# XSS 测试
curl "http://your-domain.com/?name=<script>alert(1)</script>"
# 预期: 403 Forbidden

# 命令注入测试
curl "http://your-domain.com/?cmd=cat /etc/passwd"
# 预期: 403 Forbidden

# 路径遍历测试
curl "http://your-domain.com/?file=../../../etc/passwd"
# 预期: 403 Forbidden
```



### 查看日志

```bash
# 查看今天的攻击日志
tail -f /var/log/waf/attack_$(date +%Y-%m-%d).log

# 统计攻击类型
cat /var/log/waf/attack_*.log | jq -r '.attack_type' | sort | uniq -c | sort -rn

# 统计攻击 IP
cat /var/log/waf/attack_*.log | jq -r '.client_ip' | sort | uniq -c | sort -rn
```

---

## 📁 项目结构

```
/etc/openresty/openresty-waf/
├── conf/                      # 配置文件
│   ├── waf.lua               # 主配置
│   ├── ip_whitelist.txt      # IP 白名单
│   └── ip_blacklist.txt      # IP 黑名单
├── lib/resty/waf/            # 核心模块
│   ├── init.lua              # 入口
│   ├── core/                 # 核心引擎
│   │   ├── engine.lua
│   │   ├── config.lua
│   │   ├── request.lua
│   │   └── response.lua
│   ├── modules/              # 安全模块
│   │   ├── ip_filter.lua
│   │   ├── rate_limit.lua
│   │   ├── sql_injection.lua
│   │   ├── xss.lua
│   │   ├── path_traversal.lua
│   │   ├── cmd_injection.lua
│   │   └── encoding_bypass.lua
│   ├── rules/                # 规则引擎
│   │   ├── loader.lua
│   │   └── matcher.lua
│   └── utils/                # 工具库
│       ├── logger.lua
│       ├── ip.lua
│       └── codec.lua
├── rules/                    # 规则文件 (JSON)
│   ├── sql_injection.json
│   ├── xss.json
│   ├── cmd_injection.json
│   ├── path_traversal.json
│   └── encoding_bypass.json
├── nginx/                    # Nginx 配置示例
│   ├── waf.conf
│   └── nginx.conf
├── LICENSE
└── README.md
```

---

## 📊 性能指标

| 指标 | 数值 |
|------|------|
| 延迟增加 | < 1ms |
| 支持 QPS | 10,000+ |
| 内存占用 | ~50MB (共享字典) |
| CPU 占用 | < 5% |

---

## 🔧 运维命令

```bash
# 查看 OpenResty 状态
sudo systemctl status openresty

# 启动/停止/重启
sudo systemctl start openresty
sudo systemctl stop openresty
sudo systemctl restart openresty

# 重载配置 (不中断连接)
sudo openresty -s reload

# 测试配置
sudo openresty -t

# 查看错误日志
sudo tail -f /var/log/openresty/error.log

# 清理 7 天前的 WAF 日志
sudo find /var/log/waf/ -name "attack_*.log" -mtime +7 -delete
```

---

## ❓ 常见问题

### Q: WAF 不生效？

1. 检查 `waf.lua` 中 `waf_enable = true`
2. 检查 Nginx 错误日志：`tail -f /var/log/openresty/error.log`
3. 确认 `lua_package_path` 路径正确

### Q: 限流不生效？

1. 确认 `lua_shared_dict waf_limit` 已配置
2. 检查 `rate_limit.enable = true`
3. 静态资源可能被白名单跳过

### Q: 误报太多？

1. 设置 `mode = "monitor"` 只记录不拦截
2. 查看日志确定触发的规则
3. 在规则文件中禁用该规则：`"enabled": false`
4. 或添加 URI/IP 到白名单

### Q: 日志文件没有写入？

**常见错误**: `Permission denied` 写入日志失败

```bash
# 检查错误日志
grep "Failed to write" /var/log/openresty/error.log

# 如果看到 Permission denied，设置正确权限
sudo chown -R www-data:www-data /var/log/waf/
sudo chmod 755 /var/log/waf/

# 或者快速修复
sudo chmod 777 /var/log/waf/
```

> ⚠️ **注意**: OpenResty worker 进程通常以 `www-data` 或 `nobody` 用户运行，需要有日志目录的写权限。

**日志文件位置**:
- 按天分割: `/var/log/waf/attack_YYYY-MM-DD.log`
- 同时输出到: Nginx 错误日志 (搜索 `[WAF]`)

---

## 🤝 贡献

欢迎贡献代码！

1. Fork 本仓库
2. 创建分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

---

## 📄 许可证

[MIT License](LICENSE)

---

<div align="center">

**如果这个项目对你有帮助，请给一个 ⭐ Star！**

Made with ❤️

</div>
