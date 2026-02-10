// 节点管理 API
// GET    /api/nodes          - 获取所有节点
// GET    /api/nodes?id=xxx   - 获取单个节点
// POST   /api/nodes          - 添加节点（需认证）
// PUT    /api/nodes?id=xxx   - 更新节点（需认证）
// DELETE /api/nodes?id=xxx   - 删除节点（需认证）

// 节点数据聚合存储 Key
const NODES_DATA_KEY = 'nodes_data';

// 获取 KV 存储实例
function getKV(env) {
    // 优先使用 env.NODES_KV，如果不存在则尝试直接访问全局变量
    return env.NODES_KV || (typeof NODES_KV !== 'undefined' ? NODES_KV : null);
}

// 清除订阅缓存
async function clearSubscribeCache(env) {
    try {
        const kv = getKV(env);
        if (!kv) {
            console.warn('KV storage not available');
            return;
        }
        await kv.delete('cache:subscribe:text');
        await kv.delete('cache:subscribe:base64');
        await kv.delete('cache:subscribe:clash');
    } catch (error) {
        console.error('Error clearing subscribe cache:', error);
    }
}

export async function onRequestGet(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const id = url.searchParams.get('id');
    const format = url.searchParams.get('format');

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

        // 获取所有节点（聚合存储，一次读取）
        const data = await kv.get(NODES_DATA_KEY);
        const nodes = data ? JSON.parse(data) : [];

        // 获取单个节点
        if (id) {
            const node = nodes.find(n => n.id === id);
            if (!node) {
                return new Response(JSON.stringify({ error: 'Node not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
                });
            }
            return new Response(JSON.stringify(node), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // Base64 订阅格式
        if (format === 'base64') {
            const links = nodes.map(n => generateLink(n)).join('\n');
            const base64Data = base64Encode(links);
            return new Response(base64Data, {
                headers: { ...corsHeaders, 'Content-Type': 'text/plain; charset=utf-8' }
            });
        }

        return new Response(JSON.stringify({ success: true, nodes, count: nodes.length }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in GET /api/nodes:', error);
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
        const existingData = await kv.get(NODES_DATA_KEY);
        const nodes = existingData ? JSON.parse(existingData) : [];

        // 批量导入
        if (Array.isArray(data)) {
            const results = [];
                    for (const node of data) {
                        const id = crypto.randomUUID();
                        const nodeData = {
                            id,
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
                        nodes.push(nodeData);
                        results.push(nodeData);
                    }
                    // 保存聚合数据
                    await kv.put(NODES_DATA_KEY, JSON.stringify(nodes));            // 清除订阅缓存
            await clearSubscribeCache(env);
            return new Response(JSON.stringify({ success: true, imported: results.length, nodes: results }), {
                status: 201,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 单个添加
        const id = crypto.randomUUID();
        const nodeData = {
            id,
            name: data.name,
            type: data.type,
            server: data.server,
            port: data.port,
            password: data.password,
            network: data.network || 'tcp',
            tls: data.tls || false,
            host: data.host || '',
            path: data.path || '',
            aid: data.aid || 0,
            security: data.security || 'aes-256-gcm',
            created_at: now,
            updated_at: now
        };

        nodes.push(nodeData);
        await kv.put(NODES_DATA_KEY, JSON.stringify(nodes));
        // 清除订阅缓存
        await clearSubscribeCache(env);

        return new Response(JSON.stringify({ success: true, node: nodeData }), {
            status: 201,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in POST /api/nodes:', error);
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
        const existingData = await kv.get(NODES_DATA_KEY);
        const nodes = existingData ? JSON.parse(existingData) : [];

        const index = nodes.findIndex(n => n.id === id);
        if (index === -1) {
            return new Response(JSON.stringify({ error: 'Node not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        const data = await request.json();
        const now = Date.now();

        nodes[index] = { ...nodes[index], ...data, id, updated_at: now };
        await kv.put(NODES_DATA_KEY, JSON.stringify(nodes));
        // 清除订阅缓存
        await clearSubscribeCache(env);

        return new Response(JSON.stringify({ success: true, node: nodes[index] }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in PUT /api/nodes:', error);
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

    // 删除全部节点（没有 id 参数）
    if (!id) {
        try {
            await kv.put(NODES_DATA_KEY, JSON.stringify([]));
            // 清除订阅缓存
            await clearSubscribeCache(env);
            return new Response(JSON.stringify({ success: true, deleted: 'all' }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        } catch (error) {
            console.error('Error in DELETE all nodes:', error);
            return new Response(JSON.stringify({ error: error.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }
    }

    // 删除单个节点
    try {
        const existingData = await kv.get(NODES_DATA_KEY);
        const nodes = existingData ? JSON.parse(existingData) : [];

        const index = nodes.findIndex(n => n.id === id);
        if (index === -1) {
            return new Response(JSON.stringify({ error: 'Node not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        nodes.splice(index, 1);
        await kv.put(NODES_DATA_KEY, JSON.stringify(nodes));
        // 清除订阅缓存
        await clearSubscribeCache(env);

        return new Response(JSON.stringify({ success: true, deleted: id }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Error in DELETE /api/nodes:', error);
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
        case 'hysteria2': {
            let params = [];
            if (node.host) {
                params.push(`sni=${encodeURIComponent(node.host)}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            const paramStr = params.length > 0 ? `?${params.join('&')}` : '';
            return `hysteria2://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
        }
        case 'hy2': {
            let params = [];
            if (node.host) {
                params.push(`sni=${encodeURIComponent(node.host)}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            const paramStr = params.length > 0 ? `?${params.join('&')}` : '';
            return `hysteria2://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
        }
        case 'hysteria': {
            let params = [];
            if (node.host) {
                params.push(`sni=${encodeURIComponent(node.host)}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            const paramStr = params.length > 0 ? `?${params.join('&')}` : '';
            return `hysteria://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
        }
        case 'hy1': {
            let params = [];
            if (node.host) {
                params.push(`sni=${encodeURIComponent(node.host)}`);
            }
            if (node.path) {
                params.push(`path=${encodeURIComponent(node.path)}`);
            }
            if (node.tls) {
                params.push('security=tls');
            }
            const paramStr = params.length > 0 ? `?${params.join('&')}` : '';
            return `hysteria://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
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
