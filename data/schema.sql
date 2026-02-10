-- 节点表
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- vmess, vless, ss, trojan
    server TEXT NOT NULL,
    port INTEGER NOT NULL,
    password TEXT NOT NULL,
    network TEXT DEFAULT 'tcp', -- tcp, ws, h2, grpc
    tls BOOLEAN DEFAULT FALSE,
    host TEXT,
    path TEXT,
    aid INTEGER DEFAULT 0, -- VMess Alter ID
    security TEXT DEFAULT 'aes-256-gcm', -- Shadowsocks 加密方法
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 订阅链接表
CREATE TABLE IF NOT EXISTS subscribe_links (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_nodes_created ON nodes(created_at);
CREATE INDEX IF NOT EXISTS idx_subscribe_links_enabled ON subscribe_links(enabled);