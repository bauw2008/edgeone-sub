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

        // Hysteria2
        if (link.startsWith('hy2://') || link.startsWith('hysteria2://')) {
            // hy2://password@server:port/?insecure=1&sni=xxx#name
            const protocol = link.startsWith('hy2://') ? 'hy2://' : 'hysteria2://';
            const linkWithoutProtocol = link.slice(protocol.length);
            
            // 分离查询参数和哈希
            const hashIndex = linkWithoutProtocol.indexOf('#');
            const pathAndQuery = hashIndex >= 0 ? linkWithoutProtocol.slice(0, hashIndex) : linkWithoutProtocol;
            const hash = hashIndex >= 0 ? decodeURIComponent(linkWithoutProtocol.slice(hashIndex + 1)) : 'Hysteria2 Node';
            
            // 分离认证信息和路径
            const atIndex = pathAndQuery.indexOf('@');
            if (atIndex === -1) return null;
            
            const authPart = pathAndQuery.slice(0, atIndex);
            const serverPart = pathAndQuery.slice(atIndex + 1);
            
            // 密码
            const password = authPart || '';
            
            // 分离服务器和端口与查询参数（处理 / 路径）
            const queryIndex = serverPart.indexOf('?');
            const serverPortPath = queryIndex >= 0 ? serverPart.slice(0, queryIndex) : serverPart;
            const queryString = queryIndex >= 0 ? serverPart.slice(queryIndex + 1) : '';
            
            // 移除路径部分，只保留 server:port
            const slashIndex = serverPortPath.indexOf('/');
            const serverAndPort = slashIndex >= 0 ? serverPortPath.slice(0, slashIndex) : serverPortPath;
            
            // 解析服务器和端口
            const lastColon = serverAndPort.lastIndexOf(':');
            if (lastColon === -1) return null;
            const server = serverAndPort.slice(0, lastColon);
            const port = parseInt(serverAndPort.slice(lastColon + 1)) || 443;
            
            // 解析查询参数
            const params = new URLSearchParams(queryString);
            
            return {
                name: hash || 'Hysteria2 Node',
                type: 'hysteria2',
                server,
                port,
                password,
                network: 'udp',
                host: params.get('sni') || '',
                path: '',
                insecure: params.get('insecure') === '1',
                sni: params.get('sni') || ''
            };
        }

        // Hysteria1
        if (link.startsWith('hysteria://')) {
            // hysteria://server:port/?insecure=1&peer=xxx&auth=password&upmbps=100&downmbps=100&alpn=h3#name
            const linkWithoutProtocol = link.slice('hysteria://'.length);
            
            // 分离查询参数和哈希
            const hashIndex = linkWithoutProtocol.indexOf('#');
            const pathAndQuery = hashIndex >= 0 ? linkWithoutProtocol.slice(0, hashIndex) : linkWithoutProtocol;
            const hash = hashIndex >= 0 ? decodeURIComponent(linkWithoutProtocol.slice(hashIndex + 1)) : 'Hysteria Node';
            
            // 分离服务器和端口与查询参数（处理 / 路径）
            const queryIndex = pathAndQuery.indexOf('?');
            const serverPortPath = queryIndex >= 0 ? pathAndQuery.slice(0, queryIndex) : pathAndQuery;
            const queryString = queryIndex >= 0 ? pathAndQuery.slice(queryIndex + 1) : '';
            
            // 移除路径部分，只保留 server:port
            const slashIndex = serverPortPath.indexOf('/');
            const serverAndPort = slashIndex >= 0 ? serverPortPath.slice(0, slashIndex) : serverPortPath;
            
            // 解析服务器和端口
            const lastColon = serverAndPort.lastIndexOf(':');
            if (lastColon === -1) return null;
            const server = serverAndPort.slice(0, lastColon);
            const port = parseInt(serverAndPort.slice(lastColon + 1)) || 443;
            
            // 解析查询参数
            const params = new URLSearchParams(queryString);
            
            return {
                name: hash || 'Hysteria Node',
                type: 'hysteria',
                server,
                port,
                password: params.get('auth') || '',
                network: 'udp',
                host: params.get('peer') || params.get('sni') || '',
                path: '',
                insecure: params.get('insecure') === '1',
                sni: params.get('sni') || params.get('peer') || '',
                alpn: params.get('alpn') || '',
                upmbps: params.get('upmbps') || '',
                downmbps: params.get('downmbps') || ''
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