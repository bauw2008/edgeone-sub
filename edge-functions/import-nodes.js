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

        // 获取现有节点数据
        const existingData = await NODES_KV.get('nodes_data');
        const existingNodes = existingData ? JSON.parse(existingData) : [];

        // 合并新节点
        const mergedNodes = [...existingNodes];
        const seen = new Set(existingNodes.map(n => `${n.type}-${n.server}-${n.port}`));

        for (const node of uniqueNodes) {
            const key = `${node.type}-${node.server}-${node.port}`;
            if (!seen.has(key)) {
                const id = crypto.randomUUID();
                const nodeData = {
                    ...node,
                    id,
                    created_at: Date.now(),
                    updated_at: Date.now()
                };
                mergedNodes.push(nodeData);
                seen.add(key);
            }
        }

        // 保存聚合数据
        await NODES_KV.put('nodes_data', JSON.stringify(mergedNodes));

        const result = {
            success: true,
            imported: uniqueNodes.length,
            total: allNodes.length,
            unique: uniqueNodes.length,
            existing: existingNodes.length,
            merged: mergedNodes.length
        };

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

// 解析单个链接（与 admin/app.js parseLink 保持一致）
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
            // 移除 URL fragment (# 及后面的内容)，避免影响 URL 解析
            const linkWithoutFragment = link.split('#')[0];
            const url = new URL(linkWithoutFragment);
            const params = new URLSearchParams(url.search);
            // 从原始链接中提取 name
            const nameMatch = link.match(/#(.+)$/);
            const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'VLESS Node';
            return {
                name: name,
                type: 'vless',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                network: params.get('type') || 'tcp',
                host: params.get('host') || '',
                path: params.get('path') || '',
                tls: params.get('security') === 'tls',
                sni: params.get('sni') || '',
                flow: params.get('flow') || '',
                fp: params.get('fp') || '',
                security: params.get('security') || '',
                pbk: params.get('pbk') || '',
                sid: params.get('sid') || ''
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
                tls: params.get('security') === 'tls',
                sni: params.get('sni') || '',
                allowInsecure: params.get('allowInsecure') === '1'
            };
        }

        // Hysteria1
        if (link.startsWith('hysteria://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria1 Node',
                type: 'hy1',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                protocol: params.get('protocol') || 'udp',
                obfs: params.get('obfs') || 'plain',
                auth: params.get('auth') || '',
                insecure: params.get('peer') ? true : false,
                sni: params.get('peer') || params.get('sni') || '',
                upmbps: params.get('upmbps') || '',
                downmbps: params.get('downmbps') || '',
                alpn: params.get('alpn') || ''
            };
        }

        // Hysteria2
        if (link.startsWith('hy2://') || link.startsWith('hysteria2://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria2 Node',
                type: 'hy2',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                sni: params.get('sni') || params.get('peer') || '',
                insecure: params.get('insecure') === '1'
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