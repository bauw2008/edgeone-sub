// 数据导入工具（一次性使用）
// 访问 /import-nodes 使用 Authorization: Bearer import_<密码>

export async function onRequestGet(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // 简单密码保护
    const authHeader = request.headers.get('Authorization');
    const expectedToken = 'import_' + (env.ADMIN_PASSWORD || 'default');
    if (authHeader !== `Bearer ${expectedToken}`) {
        return new Response('Unauthorized. Use Authorization: Bearer import_<password>', {
            status: 401,
            headers: corsHeaders
        });
    }

    try {
        // 读取 sub.txt 和 scatter.txt
        const subResponse = await fetch(`${url.origin}/sub.txt`);
        const scatterResponse = await fetch(`${url.origin}/scatter.txt`);

        const subContent = subResponse.ok ? await subResponse.text() : '';
        const scatterContent = scatterResponse.ok ? await scatterResponse.text() : '';

        // 解析节点
        const subNodes = parseNodes(subContent);
        const scatterNodes = parseNodes(scatterContent);
        const allNodes = [...subNodes, ...scatterNodes];

        // 去重
        const uniqueNodes = [];
        const seen = new Set();
        for (const node of allNodes) {
            const key = `${node.type}-${node.server}-${node.port}`;
            if (!seen.has(key)) {
                seen.add(key);
                uniqueNodes.push(node);
            }
        }

        // 导入到 KV
        let imported = 0;
        for (const node of uniqueNodes) {
            const id = crypto.randomUUID();
            const nodeData = { ...node, id, created: Date.now() };
            await NODES_KV.put(`node:${id}`, JSON.stringify(nodeData));
            imported++;
        }

        const result = {
            success: true,
            imported,
            total: allNodes.length,
            unique: uniqueNodes.length
        };

        return new Response(JSON.stringify(result, null, 2), {
            headers: {
                ...corsHeaders,
                'Content-Type': 'application/json; charset=utf-8'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }, null, 2), {
            status: 500,
            headers: corsHeaders
        });
    }
}

// 解析节点链接
function parseNodes(content) {
    if (!content) return [];

    const lines = content.split('\n').filter(l => l.trim());
    const nodes = [];

    for (const line of lines) {
        const node = parseLink(line.trim());
        if (node) {
            nodes.push(node);
        }
    }

    return nodes;
}

// 解析单个链接
function parseLink(link) {
    try {
        // VMess
        if (link.startsWith('vmess://')) {
            const base64Data = link.slice(8);
            const json = base64Decode(base64Data);
            const cfg = JSON.parse(json);
            return {
                name: cfg.ps || 'VMess Node',
                type: 'vmess',
                server: cfg.add,
                port: parseInt(cfg.port),
                password: cfg.id,
                aid: cfg.aid || '0',
                network: cfg.net || 'tcp',
                host: cfg.host || '',
                path: cfg.path || '',
                tls: cfg.tls === 'tls'
            };
        }

        // VLESS
        if (link.startsWith('vless://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'VLESS Node',
                type: 'vless',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                network: params.get('type') || 'tcp',
                host: params.get('host') || '',
                path: params.get('path') || '',
                tls: params.get('security') === 'tls'
            };
        }

        // Shadowsocks
        if (link.startsWith('ss://')) {
            const url = new URL(link);
            let method = 'aes-256-gcm';
            let password = '';

            if (url.username) {
                try {
                    const decoded = base64Decode(url.username);
                    const parts = decoded.split(':');
                    if (parts.length >= 2) {
                        method = parts[0];
                        password = parts.slice(1).join(':');
                    } else {
                        password = decoded;
                    }
                } catch (e) {
                    password = decodeURIComponent(url.username);
                }
            }

            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'SS Node',
                type: 'ss',
                server: url.hostname,
                port: parseInt(url.port) || 8388,
                password: password,
                security: method
            };
        }

        // Trojan
        if (link.startsWith('trojan://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'Trojan Node',
                type: 'trojan',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                network: params.get('type') || 'tcp',
                host: params.get('host') || '',
                path: params.get('path') || '',
                tls: params.get('security') === 'tls' || true
            };
        }

        // Hysteria/Hysteria2
        if (link.startsWith('hysteria://') || link.startsWith('hysteria2://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria Node',
                type: 'hysteria2',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                network: 'udp',
                host: params.get('sni') || '',
                path: '',
                tls: params.get('security') === 'tls'
            };
        }
    } catch (e) {
        console.error('Parse error:', e);
    }
    return null;
}

// Base64 解码（支持 Unicode）
function base64Decode(str) {
    try {
        return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
    } catch (e) {
        return atob(str);
    }
}