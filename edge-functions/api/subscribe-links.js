// 订阅链接管理 API
// GET    /api/subscribe-links          - 获取所有订阅链接
// GET    /api/subscribe-links?id=xxx   - 获取单个订阅链接
// POST   /api/subscribe-links          - 添加订阅链接（需认证）
// PUT    /api/subscribe-links?id=xxx   - 更新订阅链接（需认证）
// DELETE /api/subscribe-links?id=xxx   - 删除订阅链接（需认证）
// GET    /api/subscribe-links/import?id=xxx - 从订阅导入节点（需认证）

// 订阅链接聚合存储 Key
const SUBSCRIBELINKS_DATA_KEY = 'subscribelinks_data';

// 获取 KV 存储实例
function getKV(env) {
    return env.NODES_KV || (typeof NODES_KV !== 'undefined' ? NODES_KV : null);
}

export async function onRequestGet(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const id = url.searchParams.get('id');
    const action = url.searchParams.get('action');

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    try {
        const kv = getKV(env);
        if (!kv) {
            return new Response(JSON.stringify({ error: 'KV storage not configured' }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 从订阅导入节点
        if (action === 'import' && id) {
            return await importFromSubscribe(context, id, corsHeaders);
        }

        // 获取所有订阅链接（聚合存储，一次读取）
        const data = await kv.get(SUBSCRIBELINKS_DATA_KEY);
        const links = data ? JSON.parse(data) : [];

        // 获取单个订阅链接
        if (id) {
            const link = links.find(l => l.id === id);
            if (!link) {
                return new Response(JSON.stringify({ error: 'Subscribe link not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                });
            }
            return new Response(JSON.stringify(link), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        return new Response(JSON.stringify({ success: true, links, count: links.length }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in GET /api/subscribe-links:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

export async function onRequestPost(context) {
    const { request, env } = context;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // 验证认证
    const auth = verifyAuth(request, env);
    if (!auth) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    const kv = getKV(env);
    if (!kv) {
        return new Response(JSON.stringify({ error: 'KV storage not configured' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    try {
        const data = await request.json();
        const now = Date.now();

        // 获取现有数据
        const existingData = await kv.get(SUBSCRIBELINKS_DATA_KEY);
        const links = existingData ? JSON.parse(existingData) : [];

        // 添加订阅链接
        const id = crypto.randomUUID();
        const linkData = {
            id,
            name: data.name,
            url: data.url,
            enabled: data.enabled !== undefined ? data.enabled : true,
            created_at: now,
            updated_at: now
        };

        links.push(linkData);
        await kv.put(SUBSCRIBELINKS_DATA_KEY, JSON.stringify(links));

        return new Response(JSON.stringify({ success: true, link: linkData }), {
            status: 201,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in POST /api/subscribe-links:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

export async function onRequestPut(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const id = url.searchParams.get('id');

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // 验证认证
    const auth = verifyAuth(request, env);
    if (!auth) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    if (!id) {
        return new Response(JSON.stringify({ error: 'ID required' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    try {
        const existingData = await kv.get(SUBSCRIBELINKS_DATA_KEY);
        const links = existingData ? JSON.parse(existingData) : [];

        const index = links.findIndex(l => l.id === id);
        if (index === -1) {
            return new Response(JSON.stringify({ error: 'Subscribe link not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        const data = await request.json();
        const now = Date.now();

        links[index] = { ...links[index], ...data, id, updated_at: now };
        await kv.put(SUBSCRIBELINKS_DATA_KEY, JSON.stringify(links));

        return new Response(JSON.stringify({ success: true, link: links[index] }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in PUT /api/subscribe-links:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

export async function onRequestDelete(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const id = url.searchParams.get('id');

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // 验证认证
    const auth = verifyAuth(request, env);
    if (!auth) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    const kv = getKV(env);
    if (!kv) {
        return new Response(JSON.stringify({ error: 'KV storage not configured' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    // 删除全部订阅链接（没有 id 参数）
    if (!id) {
        try {
            await kv.put(SUBSCRIBELINKS_DATA_KEY, JSON.stringify([]));
            return new Response(JSON.stringify({ success: true, deleted: 'all' }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        } catch (error) {
            console.error('Error in DELETE all subscribe links:', error);
            return new Response(JSON.stringify({ error: error.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }
    }

    // 删除单个订阅链接
    try {
        const existingData = await kv.get(SUBSCRIBELINKS_DATA_KEY);
        const links = existingData ? JSON.parse(existingData) : [];

        const index = links.findIndex(l => l.id === id);
        if (index === -1) {
            return new Response(JSON.stringify({ error: 'Subscribe link not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        links.splice(index, 1);
        await kv.put(SUBSCRIBELINKS_DATA_KEY, JSON.stringify(links));

        return new Response(JSON.stringify({ success: true, deleted: id }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in DELETE /api/subscribe-links:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

// 从订阅导入节点
async function importFromSubscribe(context, id, corsHeaders) {
    const { request, env } = context;

    // 验证认证
    const auth = verifyAuth(request, env);
    if (!auth) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }

    try {
        // 获取订阅链接信息
        const linksData = await kv.get(SUBSCRIBELINKS_DATA_KEY);
        const links = linksData ? JSON.parse(linksData) : [];
        const link = links.find(l => l.id === id);

        if (!link) {
            return new Response(JSON.stringify({ error: 'Subscribe link not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 检查是否启用
        if (!link.enabled) {
            return new Response(JSON.stringify({ error: 'Subscribe link is disabled' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 获取订阅内容
        const response = await fetch(link.url);
        if (!response.ok) {
            throw new Error('Failed to fetch subscribe content');
        }

        let content = await response.text();

        // 尝试 Base64 解码
        try {
            const decoded = atob(content);
            content = decoded;
        } catch (e) {
            // 不是 Base64，直接使用
        }

        // 解析节点链接
        const lines = content.split('\n').filter(l => l.trim());
        const nodes = [];
        lines.forEach(line => {
            const node = parseLink(line.trim());
            if (node) {
                nodes.push(node);
            }
        });

        if (nodes.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid nodes found' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 批量保存节点到聚合存储
        const now = Date.now();
        const existingNodesData = await kv.get('nodes_data');
        const existingNodes = existingNodesData ? JSON.parse(existingNodesData) : [];

        const results = [];
        for (const node of nodes) {
            const nodeId = crypto.randomUUID();
            const nodeData = {
                id: nodeId,
                name: node.name,
                type: node.type,
                server: node.server,
                port: node.port,
                password: node.password,
                network: node.network || 'tcp',
                tls: node.tls || false,
                host: node.host || '',
                path: node.path || '',
                aid: node.aid || 0,
                security: node.security || 'aes-256-gcm',
                created_at: now,
                updated_at: now
            };
            // 根据节点类型添加特定字段
            if (node.type === 'vless') {
                nodeData.sni = node.sni || '';
                nodeData.flow = node.flow || '';
                nodeData.fp = node.fp || '';
                nodeData.pbk = node.pbk || '';
                nodeData.sid = node.sid !== undefined ? node.sid : '';
            } else if (node.type === 'trojan') {
                nodeData.sni = node.sni || '';
                nodeData.allowInsecure = node.allowInsecure || false;
            } else if (node.type === 'hy1' || node.type === 'hy2') {
                nodeData.sni = node.sni || '';
                nodeData.insecure = node.insecure || false;
                if (node.type === 'hy1') {
                    nodeData.upmbps = node.upmbps || '';
                    nodeData.downmbps = node.downmbps || '';
                    nodeData.alpn = node.alpn || '';
                }
            }
            existingNodes.push(nodeData);
            results.push(nodeData);
        }

        await kv.put('nodes_data', JSON.stringify(existingNodes));

        return new Response(JSON.stringify({ success: true, imported: results.length, nodes: results }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in importFromSubscribe:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

// 验证认证
function verifyAuth(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }

    const token = authHeader.slice(7);
    const expectedToken = generateToken(env.ADMIN_PASSWORD || '');

    if (token !== expectedToken) {
        return null;
    }

    return { token };
}

// 生成认证 Token
function generateToken(password) {
    if (!password) return '';
    return btoa(password + '_token_2024');
}

// 解析节点链接
function parseLink(link) {
    try {
        // VMess 链接解析
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

// VLESS 链接解析
        if (link.startsWith('vless://')) {
            // 提取基本信息
            const basicMatch = link.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)/);
            if (!basicMatch) return null;

            const password = basicMatch[1];
            const server = basicMatch[2];
            const port = parseInt(basicMatch[3]);

            // 提取参数字符串和节点名称
            const questionIndex = link.indexOf('?');
            let queryString = '';
            let name = 'VLESS Node';

            if (questionIndex > 0) {
                // 检查最后一个 # 是否是节点名称
                const lastHashIndex = link.lastIndexOf('#');
                if (lastHashIndex > 0) {
                    const beforeHash = link.substring(0, lastHashIndex);
                    const fragment = link.substring(lastHashIndex + 1);
                    
                    // 只有当 # 前面是 ? 或 & 时，才是节点名称
                    // 如果 # 前面是 =，说明这是参数值的一部分
                    const lastChar = beforeHash.charAt(beforeHash.length - 1);
                    if (lastChar === '?' || lastChar === '&') {
                        // 这是节点名称
                        name = decodeURIComponent(fragment);
                        queryString = link.substring(questionIndex + 1, lastHashIndex);
                    } else {
                        // 这是参数值的一部分，解析到末尾
                        queryString = link.substring(questionIndex + 1);
                    }
                } else {
                    queryString = link.substring(questionIndex + 1);
                }
            }

            // 解析参数
            const params = {};
            if (queryString) {
                const pairs = queryString.split('&');
                for (const pair of pairs) {
                    const eqIndex = pair.indexOf('=');
                    if (eqIndex >= 0) {
                        const key = pair.substring(0, eqIndex);
                        const value = decodeURIComponent(pair.substring(eqIndex + 1));
                        params[key] = value;
                    }
                }
            }

            return {
                name: name,
                type: 'vless',
                server: server,
                port: port,
                password: password,
                network: params['type'] || 'tcp',
                host: params['host'] || '',
                path: params['path'] || '',
                tls: params['security'] === 'tls',
                sni: params['sni'] || '',
                flow: params['flow'] || '',
                fp: params['fp'] || '',
                security: params['security'] || '',
                pbk: params['pbk'] || '',
                sid: params['sid'] || ''
            };
        }

        // Shadowsocks 链接解析
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

        // Trojan 链接解析
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
    } catch (e) {
        console.error('解析链接失败:', e);
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