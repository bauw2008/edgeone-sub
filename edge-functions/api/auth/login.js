// 用户登录 API
// POST /api/auth/login

export async function onRequestPost(context) {
    const { request, env } = context;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    try {
        console.log('Login attempt started');
        const data = await request.json();
        const { password } = data;

        if (!password) {
            return new Response(JSON.stringify({ error: 'Password required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 检查是否配置了管理员密码
        const adminPassword = env.ADMIN_PASSWORD || '';

        console.log('Password check:', { hasPassword: !!adminPassword });

        // 如果未配置密码，允许任何密码登录（仅开发环境）
        if (!adminPassword) {
            console.warn('WARNING: ADMIN_PASSWORD not configured!');
            return new Response(JSON.stringify({
                success: true,
                token: generateToken(password),
                warning: 'Admin password not configured. Set ADMIN_PASSWORD environment variable.'
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        // 验证密码
        if (password === adminPassword) {
            return new Response(JSON.stringify({
                success: true,
                token: generateToken(password),
                expiresIn: 86400 // 24小时
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
            });
        }

        return new Response(JSON.stringify({ error: 'Invalid password' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });

    } catch (error) {
        console.error('Login error:', error);
        return new Response(JSON.stringify({ error: error.message, stack: error.stack }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' }
        });
    }
}

// 生成认证 Token
function generateToken(password) {
    if (!password) return '';
    return btoa(password + '_token_2024');
}