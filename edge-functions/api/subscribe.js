// 订阅服务 API
// GET /api/subscribe           - 纯文本订阅
// GET /api/subscribe?format=base64 - Base64 订阅
// GET /api/subscribe?clash     - Clash 配置

// 缓存 Key 前缀
const CACHE_PREFIX = 'cache:subscribe:';

// 获取 KV 存储实例
function getKV(env) {
    return env.NODES_KV || (typeof NODES_KV !== 'undefined' ? NODES_KV : null);
}

export async function onRequestGet(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const format = url.searchParams.get('format');
    const isClash = url.searchParams.get('clash') !== null;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };

    try {
        const kv = getKV(env);
        if (!kv) {
            return new Response(JSON.stringify({ error: 'KV storage not configured' }), {
                status: 500,
                headers: corsHeaders
            });
        }

        // 确定缓存 Key
        let cacheKey;
        if (isClash) {
            cacheKey = `${CACHE_PREFIX}clash`;
        } else if (format === 'base64') {
            cacheKey = `${CACHE_PREFIX}base64`;
        } else {
            cacheKey = `${CACHE_PREFIX}text`;
        }

        // 尝试从缓存获取
        const cached = await kv.get(cacheKey);
        if (cached) {
            const contentType = isClash ? 'text/yaml; charset=utf-8' : 'text/plain; charset=utf-8';
            return new Response(cached, {
                headers: {
                    ...corsHeaders,
                    'Content-Type': contentType,
                    'X-Cache': 'HIT'
                }
            });
        }

        // 缓存未命中，从 KV 获取所有节点
        const data = await kv.get('nodes_data');
        const nodes = data ? JSON.parse(data) : [];

        if (nodes.length === 0) {
            return new Response('No nodes available', {
                status: 404,
                headers: corsHeaders
            });
        }

        // 生成链接
        const links = nodes.map(n => generateLink(n)).join('\n');

        let content;
        let contentType;

        // Clash 格式
        if (isClash) {
            content = await convertToClash(links, env.CLASH_CONVERT_API);
            contentType = 'text/yaml; charset=utf-8';
        } else if (format === 'base64') {
            // Base64 格式
            content = base64Encode(links);
            contentType = 'text/plain; charset=utf-8';
        } else {
            // 默认纯文本格式
            content = links;
            contentType = 'text/plain; charset=utf-8';
        }

        // 缓存结果（5分钟过期）
        await kv.put(cacheKey, content, {
            expirationTtl: 300
        });

        return new Response(content, {
            headers: {
                ...corsHeaders,
                'Content-Type': contentType,
                'X-Cache': 'MISS'
            }
        });

    } catch (error) {
        console.error('Error in GET /api/subscribe:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: corsHeaders
        });
    }
}

// 清除订阅缓存（节点数据变化时调用）
export async function clearSubscribeCache(env) {
    try {
        const kv = getKV(env);
        if (!kv) {
            console.warn('KV storage not available');
            return;
        }
        await kv.delete(`${CACHE_PREFIX}text`);
        await kv.delete(`${CACHE_PREFIX}base64`);
        await kv.delete(`${CACHE_PREFIX}clash`);
    } catch (error) {
        console.error('Error clearing subscribe cache:', error);
    }
}

// 生成节点链接
function generateLink(node) {
    switch (node.type) {
        case 'vmess': {
            const config = {
                v: '2',
                ps: node.name,
                add: node.server,
                port: node.port,
                id: node.password,
                aid: node.aid || '0',
                net: node.network || 'tcp',
                type: 'none',
                host: node.host || '',
                path: node.path || '',
                tls: node.tls ? 'tls' : ''
            };
            return 'vmess://' + base64Encode(JSON.stringify(config));
        }
        case 'vless': {
            let params = ['encryption=none'];
            if (node.network && node.network !== 'tcp') {
                params.push(`type=${node.network}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.host) {
                params.push(`host=${encodeURIComponent(node.host)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            return `vless://${node.password}@${node.server}:${node.port}?${params.join('&')}#${encodeURIComponent(node.name)}`;
        }
        case 'ss': {
            const method = node.security || 'aes-256-gcm';
            const auth = base64Encode(`${method}:${node.password}`);
            return `ss://${auth}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
        }
        case 'trojan': {
            let params = [];
            if (node.network && node.network !== 'tcp') {
                params.push(`type=${node.network}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.host) {
                params.push(`host=${encodeURIComponent(node.host)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            const paramStr = params.length > 0 ? `?${params.join('&')}` : '';
            return `trojan://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
        }
        default:
            return '';
    }
}

// Base64 编码（支持 Unicode）
function base64Encode(str) {
    try {
        return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));
    } catch (e) {
        return btoa(str);
    }
}

// 转换为 Clash 配置
async function convertToClash(links, convertApi) {
    const apiUrl = convertApi || 'https://v2ray2clash.netlify.app/.netlify/functions/clash';

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: links
        });
        if (response.ok) {
            return await response.text();
        }
    } catch (e) {
        console.error('Clash conversion failed:', e);
    }

    // 失败时返回基础配置
    return generateBasicClashConfig();
}

// 生成基础 Clash 配置
function generateBasicClashConfig() {
    return `mixed-port: 7890
allow-lan: true
mode: rule
log-level: info

proxies: []

proxy-groups:
  - name: "Auto Select"
    type: url-test
    proxies: []
    url: http://www.gstatic.com/generate_204
    interval: 300

  - name: "Manual Select"
    type: select
    proxies: []

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Auto Select
`;
}