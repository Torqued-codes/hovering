function scanURL(url) {
    const tests = [
        {
            name: 'SQL Injection',
            patterns: ["'", '"', 'or 1=1', 'union select']
        },
        {
            name: 'XSS',
            patterns: ['<script', 'javascript:', 'onerror=', 'onload=']
        },
        {
            name: 'HTTPS Check',
            custom: (url) => !url.startsWith('https://')
        },
        {
            name: 'Directory Traversal',
            patterns: ['../', '..\\', '%2e%2e']
        },
        {
            name: 'Command Injection',
            patterns: ['|', ';', '&&', '`', '$(']
        },
        {
            name: 'Open Redirect',
            patterns: ['redirect=', 'url=', 'next=', 'return=']
        },
        {
            name: 'URL Shortener',
            custom: (url) => {
                const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io', 'tiny.cc', 'rb.gy'];
                return shorteners.some(s => url.includes(s));
            }
        },
        {
            name: 'IP Address URL',
            custom: (url) => /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)
        },
        {
            name: 'Fake Domain',
            custom: (url) => {
                const fakes = ['paypa1', 'arnazon', 'g00gle', 'faceb00k', 'micros0ft', 'app1e', 'netfl1x', 'lnstagram', 'twltter', 'linkedln'];
                return fakes.some(f => url.toLowerCase().includes(f));
            }
        },
        {
            name: 'Phishing Keywords',
            custom: (url) => {
                const keywords = ['login-verify', 'account-suspended', 'verify-now', 'update-billing', 'confirm-identity', 'secure-login', 'account-locked', 'unusual-activity', 'verify-account', 'password-reset'];
                return keywords.some(k => url.toLowerCase().includes(k));
            }
        },
        {
            name: 'Suspicious TLD',
            custom: (url) => {
                const tlds = ['.xyz', '.top', '.club', '.work', '.click', '.loan', '.gq', '.ml', '.cf', '.tk'];
                return tlds.some(t => url.toLowerCase().includes(t));
            }
        },
        {
            name: 'Data Theft Patterns',
            patterns: ['passwd=', 'password=', 'creditcard=', 'ssn=', 'cvv=', 'bankaccount=']
        }
    ];

    let vulnerable = 0;
    const urlLower = url.toLowerCase();

    tests.forEach(test => {
        if (test.custom) {
            if (test.custom(url)) vulnerable++;
        } else {
            if (test.patterns.some(p => urlLower.includes(p.toLowerCase()))) {
                vulnerable++;
            }
        }
    });

    return { vulnerable, safe: tests.length - vulnerable, total: tests.length };
}

document.addEventListener('mouseover', function(e) {
    const link = e.target.closest('a');
    if (!link || !link.href) return;

    var old = document.getElementById('mypopup');
    if (old) old.remove();

    const result = scanURL(link.href);
    const v = result.vulnerable;
    const color = v === 0 ? 'cyan' : v <= 2 ? 'yellow' : 'red';
    const risk = v === 0 ? '✅ SAFE' : v <= 2 ? '⚠️ MODERATE' : '🚨 HIGH RISK';

    var div = document.createElement('div');
    div.id = 'mypopup';
    div.style.cssText = 'position:fixed;top:' + (e.clientY+20) + 'px;left:' + (e.clientX+20) + 'px;background:#1a1a2e;color:white;padding:10px 15px;border-radius:8px;z-index:99999999;font-size:14px;border:2px solid ' + color + ';min-width:180px;pointer-events:none;';
    div.innerHTML = '<div style="font-size:11px;color:#aaa;margin-bottom:4px">' + link.href.slice(0,35) + '...</div>'
        + '<div style="font-size:16px;font-weight:bold;color:' + color + '">' + risk + '</div>'
        + '<div style="font-size:11px;color:#ccc;margin-top:4px">⚠️ ' + v + ' threats &nbsp; ✅ ' + result.safe + ' safe</div>';
    document.body.appendChild(div);
});

document.addEventListener('mouseout', function(e) {
    if (e.target.closest('a')) {
        var p = document.getElementById('mypopup');
        if (p) p.remove();
    }
});

