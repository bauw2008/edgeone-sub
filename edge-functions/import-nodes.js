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
            // 智能处理 fragment：只有在 # 后面跟着的是可读的名称时才视为 fragment
            // 如果 # 在 & 后面且参数中没有明确的 name，那可能是参数值的一部分
            let name = 'VLESS Node';
            let linkWithoutFragment = link;

            // 检查是否包含 fragment，且 fragment 不是参数值的一部分
            const hashIndex = link.indexOf('#', 8); // 从 vless:// 之后开始查找
            if (hashIndex > 0) {
                // 检查 # 前面是否有 = (参数分隔符)
                const beforeHash = link.substring(0, hashIndex);
                const lastEqualsIndex = beforeHash.lastIndexOf('=');
                const lastAmpersandIndex = beforeHash.lastIndexOf('&');

                // 如果 # 前面最近的是 & 或 ?，说明这是参数值的一部分，不是 fragment
                // 如果 # 前面最近的是 =，说明这是 fragment（节点名称）
                const isFragment = lastEqualsIndex > lastAmpersandIndex && lastAmpersandIndex >= 0;

                if (isFragment) {
                    linkWithoutFragment = link.substring(0, hashIndex);
                    const fragment = link.substring(hashIndex + 1);
                    if (fragment && fragment.length > 0 && fragment.indexOf('=') === -1) {
                        name = decodeURIComponent(fragment);
                    }
                }
            }

            const url = new URL(linkWithoutFragment);
            const params = new URLSearchParams(url.search);

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
            // 移除 URL fragment
            const linkWithoutFragment = link.split('#')[0];
            const nameMatch = link.match(/#(.+)$/);
            const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'SS Node';

            // 尝试两种格式
            // 格式1: ss://base64(method:password)@server:port
            // 格式2: ss://base64(method:password@server:port)
            try {
                const url = new URL(linkWithoutFragment);

                // 检查是否有 @ 符号（区分格式1和格式2）
                if (url.username) {
                    // 格式1: ss://base64(method:password)@server:port
                    try {
                        const decoded = base64Decode(url.username);
                        const parts = decoded.split(':');
                        if (parts.length >= 2) {
                            // 处理 IPv6 地址，去掉方括号
                            let server = url.hostname;
                            if (server.startsWith('[') && server.endsWith(']')) {
                                server = server.slice(1, -1);
                            }
                            return {
                                name: name,
                                type: 'ss',
                                server: server,
                                port: parseInt(url.port) || 8388,
                                password: parts.slice(1).join(':'),
                                security: parts[0]
                            };
                        }
                    } catch (e) {
                        // 解码失败，尝试格式2
                    }
                }

                // 格式2: ss://base64(method:password@server:port)
                // 整个认证部分都是 base64
                const authPart = linkWithoutFragment.slice(5); // 移除 'ss://'
                const authData = base64Decode(authPart);
                const atIdx = authData.indexOf('@');
                if (atIdx > 0) {
                    const methodPassword = authData.substring(0, atIdx);
                    const serverPort = authData.substring(atIdx + 1);

                    // 解析 method:password
                    const colonIdx = methodPassword.indexOf(':');
                    if (colonIdx > 0) {
                        const method = methodPassword.substring(0, colonIdx);
                        const password = methodPassword.substring(colonIdx + 1);

                        // 解析 server:port
                        const lastColonIdx = serverPort.lastIndexOf(':');
                        if (lastColonIdx > 0) {
                            const server = serverPort.substring(0, lastColonIdx);
                            const port = parseInt(serverPort.substring(lastColonIdx + 1));

                            // 处理 IPv6 地址
                            if (server.startsWith('[') && server.endsWith(']')) {
                                return {
                                    name: name,
                                    type: 'ss',
                                    server: server.slice(1, -1),
                                    port: port,
                                    password: password,
                                    security: method
                                };
                            }

                            return {
                                name: name,
                                type: 'ss',
                                server: server,
                                port: port,
                                password: password,
                                security: method
                            };
                        }
                    }
                }

                // 所有格式都失败，返回 null
                return null;

            } catch (e) {
                console.error('SS link parse error:', e);
                return null;
            }
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