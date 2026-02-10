// API 配置
const API_BASE = '/api/nodes';
const AUTH_API = '/api/auth/login';
const SUBSCRIBE_API = '/api/subscribe-links';

// 认证相关
const AUTH_KEY = 'admin_auth';
const SUBSCRIBE_KEY = 'subscribe_links';

function getAuthHeaders() {
    const token = sessionStorage.getItem(AUTH_KEY);
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

function logout() {
    sessionStorage.removeItem(AUTH_KEY);
    window.location.href = '/'; // 返回首页
}

function checkAuth() {
    const token = sessionStorage.getItem(AUTH_KEY);
    if (!token) {
        window.location.href = '/';
    }
}

// 节点管理器
const NodeManager = {
    nodes: [],
    currentPage: 1,
    pageSize: 10,
    
    async init() {
        await this.load();
        this.render();
    },
    
    async load() {
        try {
            const response = await fetch(API_BASE, {
                headers: { ...getAuthHeaders() }
            });
            if (response.ok) {
                const data = await response.json();
                this.nodes = data.nodes || [];
            } else if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
                return;
            } else {
                showToast('加载节点失败', 'error');
                this.nodes = [];
            }
        } catch (error) {
            console.error('加载节点失败:', error);
            showToast('加载节点失败，请检查网络', 'error');
                this.nodes = [];
        }
        this.render();
    },
    
    async add(node) {
        try {
            const response = await fetch(API_BASE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify(node)
            });
            if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
                return false;
            }
            if (response.ok) {
                const data = await response.json();
                const newNode = data.node;
                this.nodes.push(newNode);
                this.render();
                return true;
            }
        } catch (error) {
            console.error('添加节点失败:', error);
        }
        return false;
    },
    
    async update(id, data) {
        try {
            const response = await fetch(`${API_BASE}?id=${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify(data)
            });
            if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
                return false;
            }
            if (response.ok) {
                const responseData = await response.json();
                const idx = this.nodes.findIndex(n => n.id === id);
                if (idx > -1) {
                    this.nodes[idx] = responseData.node;
                    this.render();
                }
                return true;
            }
        } catch (error) {
            console.error('更新节点失败:', error);
        }
        return false;
    },

    async removeNode(id) {
        try {
            const response = await fetch(`${API_BASE}?id=${id}`, {
                method: 'DELETE',
                headers: { ...getAuthHeaders() }
            });
            if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
                return false;
            }
            if (response.ok) {
                this.nodes = this.nodes.filter(n => n.id !== id);
                this.render();
                return true;
            }
        } catch (error) {
            console.error('删除节点失败:', error);
        }
        return false;
    },
    
    get(id) {
        return this.nodes.find(n => n.id === id);
    },
    
    render() {
        const tbody = document.getElementById('nodesTable');
        
        // 如果表格不存在（在非节点列表页面），则跳过
        if (!tbody) {
            return;
        }
        
        // 获取筛选后的节点
        const filteredNodes = this.getFilteredNodes();
        const totalPages = Math.ceil(filteredNodes.length / this.pageSize) || 1;
        
        // 确保当前页有效
        if (this.currentPage > totalPages) {
            this.currentPage = totalPages;
        }
        
        // 计算当前页的数据
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const pageNodes = filteredNodes.slice(startIndex, endIndex);
        
        if (pageNodes.length === 0 && filteredNodes.length > 0) {
            this.currentPage = 1;
            this.render();
            return;
        }
        
        if (filteredNodes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-8 text-center text-gray-500">暂无节点，点击"添加节点"按钮创建</td></tr>';
        } else {
            tbody.innerHTML = pageNodes.map(n => `
                <tr>
                    <td class="px-4 py-4">
                        <input type="checkbox" class="node-checkbox" data-id="${n.id}" onchange="updateSelectAll()">
                    </td>
                    <td class="px-6 py-4">
                        <span class="truncate-text" title="${n.name}">${n.name}</span>
                    </td>
                    <td class="px-6 py-4"><span class="type-badge type-${n.type}">${n.type.toUpperCase()}</span></td>
                    <td class="px-6 py-4">${n.server}</td>
                    <td class="px-6 py-4">${n.port}</td>
                    <td class="px-6 py-4"><span class="status-badge status-active">正常</span></td>
                    <td class="px-6 py-4">
                        <button class="action-btn action-share" onclick="shareNode('${n.id}')">分享</button>
                        <button class="action-btn action-edit" onclick="editNode('${n.id}')">编辑</button>
                        <button class="action-btn action-delete" onclick="deleteNode('${n.id}')">删除</button>
                    </td>
                </tr>
            `).join('');
        }
        
        document.getElementById('totalNodes').textContent = this.nodes.length;
        document.getElementById('activeNodes').textContent = this.nodes.length;
        
        // 渲染分页
        this.renderPagination(filteredNodes.length, totalPages);
        
        // 重置选择状态
        if (typeof resetSelection === 'function') {
            resetSelection();
        }
    },
    
    getFilteredNodes() {
        const searchText = (document.getElementById('searchFilter')?.value || '').toLowerCase();
        const typeFilter = document.getElementById('typeFilter')?.value || '';
        
        return this.nodes.filter(n => {
            const matchSearch = !searchText || 
                n.name.toLowerCase().includes(searchText) || 
                n.server.toLowerCase().includes(searchText);
            const matchType = !typeFilter || n.type === typeFilter;
            return matchSearch && matchType;
        });
    },
    
    renderPagination(totalItems, totalPages) {
        const pageInfo = document.getElementById('pageInfo');
        const pageNumbers = document.getElementById('pageNumbers');
        
        // 如果分页元素不存在（在非节点列表页面），则跳过
        if (!pageInfo || !pageNumbers) {
            return;
        }
        
        pageInfo.textContent = `共 ${totalItems} 条 / 第 ${this.currentPage} / ${totalPages} 页`;
        
        // 禁用/启用分页导航按钮
        const isFirstPage = this.currentPage === 1;
        const isLastPage = this.currentPage === totalPages;
        
        document.querySelector('button[onclick="changePage(\'first\')"]').disabled = isFirstPage;
        document.querySelector('button[onclick="changePage(\'prev\')"]').disabled = isFirstPage;
        document.querySelector('button[onclick="changePage(\'next\')"]').disabled = isLastPage;
        document.querySelector('button[onclick="changePage(\'last\')"]').disabled = isLastPage;
        
        // 生成页码
        let html = '';
        const maxVisible = 5;
        let startPage = Math.max(1, this.currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const isActive = i === this.currentPage;
            html += `<button onclick="goToPage(${i})" class="px-3 py-1 border rounded ${isActive ? 'bg-blue-500 text-white' : 'hover:bg-gray-100'}">${i}</button>`;
        }
        
        pageNumbers.innerHTML = html;
    }
};

// Base64 编码工具（支持 Unicode）
const Base64Tool = {
    encode(str) {
        try {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));
        } catch (e) {
            return btoa(str);
        }
    },
    decode(str) {
        try {
            return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        } catch (e) {
            return atob(str);
        }
    }
};

// 链接生成器
const LinkGenerator = {
    vmess(node) {
        const config = {
            v: '2',
            ps: node.name,
            add: node.server,
            port: node.port,
            id: node.password,
            aid: node.aid || '0',
            net: node.network || 'tcp',
            type: node.type || 'none',
            host: node.host || '',
            path: node.path || '',
            tls: node.tls ? 'tls' : ''
        };
        return 'vmess://' + Base64Tool.encode(JSON.stringify(config));
    },
    
    vless(node) {
        let params = ['encryption=none'];
        if (node.network) {
            params.push(`type=${node.network}`);
        }
        if (node.path) {
            params.push(`path=${encodeURIComponent(node.path)}`);
        }
        if (node.host) {
            params.push(`host=${encodeURIComponent(node.host)}`);
        }
        if (node.sni) {
            params.push(`sni=${encodeURIComponent(node.sni)}`);
        }
        if (node.flow) {
            params.push(`flow=${encodeURIComponent(node.flow)}`);
        }
        if (node.fp) {
            params.push(`fp=${encodeURIComponent(node.fp)}`);
        }
        if (node.security) {
            params.push(`security=${encodeURIComponent(node.security)}`);
        }
        if (node.pbk) {
            params.push(`pbk=${encodeURIComponent(node.pbk)}`);
        }
        if (node.sid !== undefined) {
            params.push(`sid=${encodeURIComponent(node.sid)}`);
        }
        if (node.tls && !node.security) {
            params.push('security=tls');
        }
        const paramStr = params.length > 0 ? `/?${params.join('&')}` : '';
        return `vless://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
    },
    
    ss(node) {
        // SS 链接格式: ss://method:password@server:port#name
        const method = node.security || 'aes-256-gcm';
        const auth = Base64Tool.encode(`${method}:${node.password}`);
        // 处理 IPv6 地址
        const server = node.server.includes(':') ? `[${node.server}]` : node.server;
        return `ss://${auth}@${server}:${node.port}#${encodeURIComponent(node.name)}`;
    },
    
    trojan(node) {
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
        if (node.sni) {
            params.push(`sni=${encodeURIComponent(node.sni)}`);
        }
        if (node.allowInsecure) {
            params.push('allowInsecure=1');
        }
        if (node.tls) {
            params.push('security=tls');
        }
        const paramStr = params.length > 0 ? `/?${params.join('&')}` : '';
        return `trojan://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
    },
    
    hy1(node) {
        let params = [];
        if (node.password) {
            params.push(`auth=${encodeURIComponent(node.password)}`);
        }
        if (node.insecure) {
            params.push('insecure=1');
        }
        if (node.sni || node.host) {
            params.push(`peer=${encodeURIComponent(node.sni || node.host)}`);
        }
        if (node.upmbps) {
            params.push(`upmbps=${node.upmbps}`);
        }
        if (node.downmbps) {
            params.push(`downmbps=${node.downmbps}`);
        }
        if (node.alpn) {
            params.push(`alpn=${node.alpn}`);
        }
        const paramStr = params.length > 0 ? `/?${params.join('&')}` : '';
        return `hysteria://${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
    },
    
    hy2(node) {
        let params = [];
        if (node.insecure) {
            params.push('insecure=1');
        }
        if (node.sni) {
            params.push(`sni=${encodeURIComponent(node.sni)}`);
        }
        const paramStr = params.length > 0 ? `/?${params.join('&')}` : '';
        return `hy2://${node.password}@${node.server}:${node.port}${paramStr}#${encodeURIComponent(node.name)}`;
    },
    
    generate(node) {
        return this[node.type] ? this[node.type](node) : '';
    }
};

// 页面加载时直接初始化
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    NodeManager.init();
});

// 全局函数
function openModal(id = null) {
    document.getElementById('nodeModal').classList.remove('hidden');
    document.getElementById('modalTitle').textContent = id ? '编辑节点' : '添加节点';
    if (id) {
        const n = NodeManager.get(id);
        document.getElementById('nodeId').value = n.id;
        document.getElementById('nodeName').value = n.name;
        document.getElementById('nodeType').value = n.type;
        document.getElementById('nodeServer').value = n.server;
        document.getElementById('nodePort').value = n.port;
        document.getElementById('nodePassword').value = n.password;
        document.getElementById('nodeNetwork').value = n.network || 'tcp';
        document.getElementById('nodeTls').checked = n.tls || false;
        document.getElementById('nodePath').value = n.path || '';
        document.getElementById('nodeHost').value = n.host || '';
        document.getElementById('nodeAid').value = n.aid || '0';
        document.getElementById('nodeSecurity').value = n.security || 'auto';
        // VLESS 字段
        document.getElementById('nodeSni').value = n.sni || '';
        document.getElementById('nodeFlow').value = n.flow || '';
        document.getElementById('nodeFp').value = n.fp || '';
        document.getElementById('nodeVlessSecurity').value = n.security || '';
        document.getElementById('nodePbk').value = n.pbk || '';
        document.getElementById('nodeSid').value = n.sid || '';
        // Trojan 字段
        document.getElementById('nodeTrojanSni').value = n.sni || '';
        document.getElementById('nodeAllowInsecure').checked = n.allowInsecure || false;
        // Hysteria 字段
        document.getElementById('nodeHyInsecure').checked = n.insecure || false;
        document.getElementById('nodeUpmbps').value = n.upmbps || '';
        document.getElementById('nodeDownmbps').value = n.downmbps || '';
        document.getElementById('nodeAlpn').value = n.alpn || '';
        document.getElementById('nodeHy2Sni').value = n.sni || '';
        document.getElementById('nodeHy2Insecure').checked = n.insecure || false;
        
        // 触发类型切换以显示正确的字段
        document.getElementById('nodeType').dispatchEvent(new Event('change'));
    } else {
        document.getElementById('nodeForm').reset();
        document.getElementById('nodeId').value = '';
        document.getElementById('nodeType').dispatchEvent(new Event('change'));
    }
}

function closeModal() {
    document.getElementById('nodeModal').classList.add('hidden');
}

async function saveNode(e) {
    e.preventDefault();
    const data = {
        name: document.getElementById('nodeName').value,
        type: document.getElementById('nodeType').value,
        server: document.getElementById('nodeServer').value,
        port: parseInt(document.getElementById('nodePort').value),
        password: document.getElementById('nodePassword').value,
        // 基本字段
        network: document.getElementById('nodeNetwork')?.value || 'tcp',
        tls: document.getElementById('nodeTls')?.checked || false,
        path: document.getElementById('nodePath')?.value || '',
        host: document.getElementById('nodeHost')?.value || '',
        aid: parseInt(document.getElementById('nodeAid')?.value || '0'),
        security: document.getElementById('nodeSecurity')?.value || 'auto',
        // VLESS Reality 字段
        sni: document.getElementById('nodeSni')?.value || '',
        flow: document.getElementById('nodeFlow')?.value || '',
        fp: document.getElementById('nodeFp')?.value || '',
        // 注意：这里用不同的字段名避免冲突
        vlessSecurity: document.getElementById('nodeVlessSecurity')?.value || '',
        pbk: document.getElementById('nodePbk')?.value || '',
        sid: document.getElementById('nodeSid')?.value || '',
        // Trojan 字段
        trojanSni: document.getElementById('nodeTrojanSni')?.value || '',
        allowInsecure: document.getElementById('nodeAllowInsecure')?.checked || false,
        // Hysteria 字段
        hyInsecure: document.getElementById('nodeHyInsecure')?.checked || false,
        upmbps: document.getElementById('nodeUpmbps')?.value || '',
        downmbps: document.getElementById('nodeDownmbps')?.value || '',
        alpn: document.getElementById('nodeAlpn')?.value || '',
        hy2Sni: document.getElementById('nodeHy2Sni')?.value || '',
        hy2Insecure: document.getElementById('nodeHy2Insecure')?.checked || false
    };
    
    // 根据类型清理字段
    if (data.type === 'vless') {
        data.security = data.vlessSecurity;
        data.sni = data.sni || data.trojanSni || data.hy2Sni || '';
        delete data.vlessSecurity;
        delete data.trojanSni;
        delete data.hy2Sni;
        delete data.hy2Insecure;
    } else if (data.type === 'trojan') {
        data.sni = data.trojanSni || data.sni || data.hy2Sni || '';
        delete data.vlessSecurity;
        delete data.trojanSni;
        delete data.pbk;
        delete data.sid;
        delete data.flow;
        delete data.fp;
        delete data.hy2Sni;
        delete data.hy2Insecure;
        delete data.hyInsecure;
        delete data.upmbps;
        delete data.downmbps;
        delete data.alpn;
    } else if (data.type === 'hy1') {
        data.insecure = data.hyInsecure;
        delete data.vlessSecurity;
        delete data.trojanSni;
        delete data.pbk;
        delete data.sid;
        delete data.flow;
        delete data.fp;
        delete data.hy2Sni;
        delete data.hy2Insecure;
        delete data.hyInsecure;
        delete data.allowInsecure;
    } else if (data.type === 'hy2') {
        data.sni = data.hy2Sni || data.sni || data.trojanSni || '';
        data.insecure = data.hy2Insecure;
        delete data.vlessSecurity;
        delete data.trojanSni;
        delete data.pbk;
        delete data.sid;
        delete data.flow;
        delete data.fp;
        delete data.hy2Sni;
        delete data.hy2Insecure;
        delete data.hyInsecure;
        delete data.allowInsecure;
        delete data.upmbps;
        delete data.downmbps;
        delete data.alpn;
    }
    
    const id = document.getElementById('nodeId').value;
    const success = id ? await NodeManager.update(id, data) : await NodeManager.add(data);
    if (success) {
        closeModal();
        showToast(id ? '更新成功' : '添加成功');
    } else {
        showToast('操作失败，请重试', 'error');
    }
}

function editNode(id) {
    openModal(id);
}

async function deleteNode(id) {
    if (confirm('确定删除此节点？')) {
        const success = await NodeManager.removeNode(id);
        if (success) {
            showToast('删除成功');
        } else {
            showToast('删除失败，请重试', 'error');
        }
    }
}

function shareNode(id) {
    const node = NodeManager.get(id);
    const link = LinkGenerator.generate(node);
    document.getElementById('shareLink').value = link;
    document.getElementById('shareBase64').value = btoa(link);
    document.getElementById('shareModal').classList.remove('hidden');
}

function closeShareModal() {
    document.getElementById('shareModal').classList.add('hidden');
}

function copyShareLink() {
    copyToClipboard(document.getElementById('shareLink').value);
}

function copyShareBase64() {
    copyToClipboard(document.getElementById('shareBase64').value);
}

async function copySubscribeLink(format = 'base64') {
    try {
        const baseUrl = `${location.origin}/api/subscribe`;
        let url;
        let msg;
        
        if (format === 'text') {
            url = baseUrl;
            msg = '纯文本订阅链接已复制';
        } else if (format === 'base64') {
            url = `${baseUrl}?format=base64`;
            msg = 'Base64 订阅链接已复制';
        } else if (format === 'clash') {
            url = `${baseUrl}?clash`;
            msg = 'Clash 订阅链接已复制';
        }
        
        copyToClipboard(url, msg);
    } catch (error) {
        showToast('复制失败', 'error');
    }
}

function parseLink(link) {
    try {
        // VMess 链接解析
        if (link.startsWith('vmess://')) {
            const base64Data = link.slice(8);
            const json = Base64Tool.decode(base64Data);
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
            // 提取节点名称（最后一个 # 后面的内容，且不包含 =）
            let name = 'VLESS Node';
            const lastHashIndex = link.lastIndexOf('#');
            if (lastHashIndex > 0) {
                const fragment = link.substring(lastHashIndex + 1);
                if (fragment.indexOf('=') === -1) {
                    name = decodeURIComponent(fragment);
                }
            }

            // 提取基本信息
            const basicMatch = link.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)/);
            if (!basicMatch) return null;

            const password = basicMatch[1];
            const server = basicMatch[2];
            const port = parseInt(basicMatch[3]);

            // 解析参数
            const questionIndex = link.indexOf('?');
            const params = {};

            if (questionIndex > 0) {
                // 找到参数部分的结束位置（在最后一个 # 之前）
                const endIndex = lastHashIndex > questionIndex ? lastHashIndex : link.length;
                const queryString = link.substring(questionIndex + 1, endIndex);

                // 简单按 & 分割参数
                const pairs = queryString.split('&');
                for (const pair of pairs) {
                    const eqIndex = pair.indexOf('=');
                    if (eqIndex > 0) {
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
                        const decoded = Base64Tool.decode(url.username);
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
                const authData = Base64Tool.decode(authPart);
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
                tls: params.get('security') === 'tls',
                sni: params.get('sni') || '',
                allowInsecure: params.get('allowInsecure') === '1'
            };
        }

        // Hysteria1 链接解析
        if (link.startsWith('hysteria://')) {
            const url = new URL(link);
            const params = new URLSearchParams(url.search);
            return {
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria1 Node',
                type: 'hy1',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: params.get('auth') || url.username || '',
                protocol: params.get('protocol') || 'udp',
                obfs: params.get('obfs') || 'plain',
                insecure: params.get('insecure') === '1',
                sni: params.get('peer') || params.get('sni') || '',
                upmbps: params.get('upmbps') || '',
                downmbps: params.get('downmbps') || '',
                alpn: params.get('alpn') || ''
            };
        }

        // Hysteria2 链接解析
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
        console.error('解析链接失败:', e);
    }
    return null;
}

async function exportNodes() {
    await NodeManager.load(); // 确保数据最新
    const links = NodeManager.nodes.map(n => LinkGenerator.generate(n)).join('\n');
    const blob = new Blob([links], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `nodes_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    showToast('节点已导出');
}

function copyToClipboard(text, msg = '已复制到剪贴板') {
    navigator.clipboard.writeText(text).then(() => showToast(msg));
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

async function loadNodes() {
    await NodeManager.load();
    showToast('刷新成功');
}

// ==================== 筛选和多选功能 ====================

// 筛选节点
function filterNodes() {
    NodeManager.currentPage = 1; // 筛选时重置到第一页
    NodeManager.render();
}

// 全选/取消全选
function toggleSelectAll() {
    const headerCheckbox = document.getElementById('headerCheckbox');
    if (!headerCheckbox) return;
    const selectAll = headerCheckbox.checked;
    document.querySelectorAll('.node-checkbox').forEach(cb => {
        cb.checked = selectAll;
    });
}

// 更新全选框状态
function updateSelectAll() {
    const checkboxes = document.querySelectorAll('.node-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    document.getElementById('headerCheckbox').checked = allChecked;
}

// 重置选择状态
function resetSelection() {
    document.getElementById('headerCheckbox').checked = false;
    document.querySelectorAll('.node-checkbox').forEach(cb => cb.checked = false);
}

// 获取选中的节点ID
function getSelectedNodeIds() {
    return Array.from(document.querySelectorAll('.node-checkbox:checked'))
        .map(cb => cb.dataset.id);
}

// 导出选中节点
async function exportSelected() {
    const selectedIds = getSelectedNodeIds();
    if (selectedIds.length === 0) {
        showToast('请先选择要导出的节点', 'error');
        return;
    }
    
    const selectedNodes = NodeManager.nodes.filter(n => selectedIds.includes(n.id));
    const links = selectedNodes.map(n => LinkGenerator.generate(n)).join('\n');
    const blob = new Blob([links], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `selected_nodes_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    showToast(`已导出 ${selectedNodes.length} 个节点`);
}

// 删除选中节点
async function deleteSelected() {
    const selectedIds = getSelectedNodeIds();
    if (selectedIds.length === 0) {
        showToast('请先选择要删除的节点', 'error');
        return;
    }
    
    if (!confirm(`确定删除选中的 ${selectedIds.length} 个节点？`)) {
        return;
    }
    
    let successCount = 0;
    for (const id of selectedIds) {
        const success = await NodeManager.removeNode(id);
        if (success) successCount++;
    }
    
    showToast(`已删除 ${successCount} 个节点`);
}

// 重置系统（清除所有数据）
async function resetSystem() {
    const nodeCount = NodeManager.nodes.length;
    const subscribeCount = SubscribeManager.links.length;
    
    // 第一次确认：警告弹窗
    if (!confirm(`⚠️ 警告：重置系统将清除所有数据！\n\n节点数量：${nodeCount}\n订阅链接数量：${subscribeCount}\n\n此操作不可恢复！`)) {
        return;
    }
    
    // 第二次确认
    if (!confirm('确定要重置系统吗？所有节点和订阅链接将被永久删除！')) {
        showToast('操作已取消', 'info');
        return;
    }
    
    try {
        // 清除所有节点
        await fetch(API_BASE, {
            method: 'DELETE',
            headers: { ...getAuthHeaders() }
        });
        
        // 清除所有订阅链接
        await fetch(SUBSCRIBE_API, {
            method: 'DELETE',
            headers: { ...getAuthHeaders() }
        });
        
        // 重新加载数据
        NodeManager.nodes = [];
        SubscribeManager.links = [];
        NodeManager.render();
        
        showToast('系统已重置，所有数据已清除', 'success');
    } catch (error) {
        console.error('重置系统失败:', error);
        showToast('重置失败，请重试', 'error');
    }
}

// ==================== 分页功能 ====================

function goToPage(page) {
    NodeManager.currentPage = page;
    NodeManager.render();
}

function changePage(action) {
    const totalPages = Math.ceil(NodeManager.getFilteredNodes().length / NodeManager.pageSize) || 1;
    
    switch(action) {
        case 'first':
            NodeManager.currentPage = 1;
            break;
        case 'prev':
            NodeManager.currentPage = Math.max(1, NodeManager.currentPage - 1);
            break;
        case 'next':
            NodeManager.currentPage = Math.min(totalPages, NodeManager.currentPage + 1);
            break;
        case 'last':
            NodeManager.currentPage = totalPages;
            break;
    }
    NodeManager.render();
}

function changePageSize() {
    NodeManager.pageSize = parseInt(document.getElementById('pageSize').value);
    NodeManager.currentPage = 1;
    NodeManager.render();
}

// ==================== 页面切换 ====================
function showPage(pageName) {
    // 隐藏所有页面
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.add('hidden');
    });

    // 显示目标页面
    const targetPage = document.getElementById(`page-${pageName}`);
    if (targetPage) {
        targetPage.classList.remove('hidden');
    }

    // 更新按钮样式
    document.querySelectorAll('.page-btn').forEach(btn => {
        if (btn.dataset.page === pageName) {
            btn.classList.remove('bg-gray-200', 'text-gray-700', 'hover:bg-gray-300');
            btn.classList.add('bg-blue-500', 'text-white');
        } else {
            btn.classList.remove('bg-blue-500', 'text-white');
            btn.classList.add('bg-gray-200', 'text-gray-700', 'hover:bg-gray-300');
        }
    });

    // 加载对应数据
    if (pageName === 'subscribe-links') {
        loadSubscribeLinks();
    }
}

// ==================== 文本导入 ====================
function clearTextEditor() {
    document.getElementById('textEditor').value = '';
}

async function saveTextImport() {
    const text = document.getElementById('textEditor').value.trim();
    if (!text) {
        showToast('请输入节点链接', 'error');
        return;
    }

    const lines = text.split('\n').filter(l => l.trim());
    const nodes = [];
    lines.forEach(line => {
        const node = parseLink(line.trim());
        if (node) {
            nodes.push(node);
        }
    });

    if (nodes.length === 0) {
        showToast('未找到有效的节点链接', 'error');
        return;
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
            body: JSON.stringify(nodes)
        });

        if (response.status === 401) {
            showToast('登录已过期，请重新登录', 'error');
            logout();
            return;
        }

        if (response.ok) {
            const result = await response.json();
            await NodeManager.load();
            document.getElementById('textEditor').value = '';
            showToast(`成功导入 ${result.imported} 个节点`);
        } else {
            showToast('导入失败', 'error');
        }
    } catch (error) {
        console.error('导入失败:', error);
        showToast('导入失败，请检查网络', 'error');
    }
}

function hideTextEditor() {
    showPage('nodes');
}

// ==================== 订阅链接管理 ====================
const SubscribeManager = {
    links: [],

    async load() {
        try {
            const response = await fetch(SUBSCRIBE_API, {
                headers: { ...getAuthHeaders() }
            });
            if (response.ok) {
                const data = await response.json();
                this.links = data.links || [];
            } else if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
            } else {
                this.links = [];
            }
        } catch (error) {
            console.error('加载订阅链接失败:', error);
            this.links = [];
        }
    },

    async add(link) {
        try {
            const response = await fetch(SUBSCRIBE_API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify(link)
            });
            if (response.ok) {
                const data = await response.json();
                this.links.push(data.link);
                this.render();
                return true;
            }
        } catch (error) {
            console.error('添加订阅链接失败:', error);
        }
        return false;
    },

    async update(id, data) {
        try {
            const response = await fetch(`${SUBSCRIBE_API}?id=${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                const responseData = await response.json();
                const idx = this.links.findIndex(l => l.id === id);
                if (idx > -1) {
                    this.links[idx] = responseData.link;
                    this.render();
                }
                return true;
            }
        } catch (error) {
            console.error('更新订阅链接失败:', error);
        }
        return false;
    },

    async remove(id) {
        try {
            const response = await fetch(`${SUBSCRIBE_API}?id=${id}`, {
                method: 'DELETE',
                headers: { ...getAuthHeaders() }
            });
            if (response.ok) {
                this.links = this.links.filter(l => l.id !== id);
                this.render();
                return true;
            }
        } catch (error) {
            console.error('删除订阅链接失败:', error);
        }
        return false;
    },

    async toggleEnabled(id, enabled) {
        return await this.update(id, { enabled });
    },

    async importFromSubscribe(id) {
        try {
            const response = await fetch(`${SUBSCRIBE_API}/import?id=${id}`, {
                headers: { ...getAuthHeaders() }
            });
            if (response.status === 401) {
                showToast('登录已过期，请重新登录', 'error');
                logout();
                return false;
            }
            if (response.ok) {
                const result = await response.json();
                await NodeManager.load();
                showToast(`成功从订阅导入 ${result.imported} 个节点`);
                return true;
            }
        } catch (error) {
            console.error('从订阅导入失败:', error);
            showToast('导入失败，请检查网络', 'error');
        }
        return false;
    },

    render() {
        const container = document.getElementById('subscribeLinksList');
        if (this.links.length === 0) {
            container.innerHTML = '<p class="text-gray-500 text-center py-8">暂无订阅链接，点击"添加订阅链接"按钮创建</p>';
        } else {
            container.innerHTML = this.links.map(link => `
                <div class="border rounded-lg p-4 hover:shadow-md transition">
                    <div class="flex justify-between items-start">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <h3 class="font-semibold text-gray-800">${link.name}</h3>
                                <span class="px-2 py-0.5 text-xs rounded ${link.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">
                                    ${link.enabled ? '已启用' : '已禁用'}
                                </span>
                            </div>
                            <p class="text-sm text-gray-600 font-mono truncate">${link.url}</p>
                            <p class="text-xs text-gray-400 mt-1">创建时间: ${new Date(link.createdAt).toLocaleString('zh-CN')}</p>
                        </div>
                        <div class="flex gap-2 ml-4">
                            <button onclick="SubscribeManager.toggleEnabled('${link.id}', ${!link.enabled})" class="px-3 py-1.5 text-sm rounded ${link.enabled ? 'bg-orange-100 text-orange-700 hover:bg-orange-200' : 'bg-green-100 text-green-700 hover:bg-green-200'}">
                                ${link.enabled ? '禁用' : '启用'}
                            </button>
                            <button onclick="SubscribeManager.importFromSubscribe('${link.id}')" class="px-3 py-1.5 text-sm rounded bg-blue-100 text-blue-700 hover:bg-blue-200" ${!link.enabled ? 'disabled' : ''}>
                                导入
                            </button>
                            <button onclick="editSubscribe('${link.id}')" class="px-3 py-1.5 text-sm rounded bg-gray-100 text-gray-700 hover:bg-gray-200">
                                编辑
                            </button>
                            <button onclick="deleteSubscribe('${link.id}')" class="px-3 py-1.5 text-sm rounded bg-red-100 text-red-700 hover:bg-red-200">
                                删除
                            </button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }
};

async function loadSubscribeLinks() {
    await SubscribeManager.load();
    SubscribeManager.render();
}

function openSubscribeModal() {
    document.getElementById('subscribeModal').classList.remove('hidden');
    document.getElementById('subscribeModalTitle').textContent = '添加订阅链接';
    document.getElementById('subscribeForm').reset();
    document.getElementById('subscribeId').value = '';
}

function closeSubscribeModal() {
    document.getElementById('subscribeModal').classList.add('hidden');
}

async function saveSubscribe(e) {
    e.preventDefault();
    const data = {
        name: document.getElementById('subscribeName').value,
        url: document.getElementById('subscribeUrl').value,
        enabled: document.getElementById('subscribeEnabled').checked
    };
    const id = document.getElementById('subscribeId').value;
    const success = id ? await SubscribeManager.update(id, data) : await SubscribeManager.add(data);
    if (success) {
        closeSubscribeModal();
        showToast(id ? '更新成功' : '添加成功');
    } else {
        showToast('操作失败，请重试', 'error');
    }
}

function editSubscribe(id) {
    const link = SubscribeManager.links.find(l => l.id === id);
    if (link) {
        document.getElementById('subscribeModal').classList.remove('hidden');
        document.getElementById('subscribeModalTitle').textContent = '编辑订阅链接';
        document.getElementById('subscribeId').value = link.id;
        document.getElementById('subscribeName').value = link.name;
        document.getElementById('subscribeUrl').value = link.url;
        document.getElementById('subscribeEnabled').checked = link.enabled;
    }
}

async function deleteSubscribe(id) {
    if (confirm('确定删除此订阅链接？')) {
        const success = await SubscribeManager.remove(id);
        if (success) {
            showToast('删除成功');
        } else {
            showToast('删除失败，请重试', 'error');
        }
    }
}
