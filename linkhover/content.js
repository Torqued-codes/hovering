function getDomain(u) {
    try { return new URL(u).hostname; } catch(e) { return u; }
}

function calcEntropy(str) {
    var freq = {};
    for (var i = 0; i < str.length; i++) {
        freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    var entropy = 0;
    var keys = Object.keys(freq);
    for (var j = 0; j < keys.length; j++) {
        var p = freq[keys[j]] / str.length;
        entropy -= p * (Math.log(p) / Math.log(2));
    }
    return entropy;
}

function scanURL(url) {
    var tests = [
        {
            name: 'SQL Injection',
            custom: function(u) {
                return ["'", '"', 'or 1=1', 'union select'].some(function(x) { return u.toLowerCase().indexOf(x) !== -1; });
            }
        },
        {
            name: 'XSS',
            custom: function(u) {
                return ['<script', 'javascript:', 'onerror=', 'onload='].some(function(x) { return u.toLowerCase().indexOf(x) !== -1; });
            }
        },
        {
            name: 'HTTPS Check',
            custom: function(u) { return u.indexOf('https://') !== 0; }
        },
        {
            name: 'Directory Traversal',
            custom: function(u) {
                return ['../', '..\\', '%2e%2e'].some(function(x) { return u.toLowerCase().indexOf(x) !== -1; });
            }
        },
        {
            name: 'Command Injection',
            custom: function(u) {
                return ['&&', '$(', '%7C'].some(function(x) { return u.indexOf(x) !== -1; });
            }
        },
        {
            name: 'Open Redirect',
            custom: function(u) {
                return ['redirect=', 'next=', 'return=', 'dest=', 'goto='].some(function(x) { return u.toLowerCase().indexOf(x) !== -1; });
            }
        },
        {
            name: 'URL Shortener',
            custom: function(u) {
                return ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io', 'tiny.cc', 'rb.gy', 'is.gd', 'buff.ly', 'cutt.ly'].some(function(x) { return u.indexOf(x) !== -1; });
            }
        },
        {
            name: 'IP Address URL',
            custom: function(u) { return /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(u); }
        },
        {
            name: 'Fake Domain',
            custom: function(u) {
                return ['paypa1','paypai','arnazon','amazom','g00gle','googie','faceb00k','facebok','micros0ft','microsft','app1e','netfl1x','lnstagram','twltter','linkedln','whatsaap','discrod'].some(function(f) { return u.toLowerCase().indexOf(f) !== -1; });
            }
        },
        {
            name: 'Phishing Keywords',
            custom: function(u) {
                return ['login-verify','account-suspended','verify-now','update-billing','confirm-identity','secure-login','account-locked','unusual-activity','verify-account','password-reset','webscr','ebayisapi','signin-','banking-'].some(function(k) { return u.toLowerCase().indexOf(k) !== -1; });
            }
        },
        {
            name: 'Suspicious TLD',
            custom: function(u) {
                var tlds = ['.xyz','.top','.club','.work','.click','.loan','.gq','.ml','.cf','.tk','.pw'];
                try {
                    var host = new URL(u).hostname;
                    return tlds.some(function(t) { return host.slice(-t.length) === t; });
                } catch(e) { return false; }
            }
        },
        {
            name: 'Data Theft Patterns',
            custom: function(u) {
                return ['passwd=','password=','creditcard=','ssn=','cvv=','bankaccount=','cardnumber=','pin='].some(function(x) { return u.toLowerCase().indexOf(x) !== -1; });
            }
        },
        {
            name: 'Excessive URL Length',
            custom: function(u) { return u.length > 150; }
        },
        {
            name: 'High URL Entropy',
            custom: function(u) {
                try { return calcEntropy(new URL(u).hostname) > 3.8; }
                catch(e) { return false; }
            }
        },
        {
            name: 'Excessive Subdomains',
            custom: function(u) {
                try { return new URL(u).hostname.split('.').length >= 6; }
                catch(e) { return false; }
            }
        },
        {
            name: 'Special Characters',
            custom: function(u) { return (u.match(/[@#~]/g) || []).length >= 3; }
        },
        {
            name: 'Brand Name in Subdomain',
            custom: function(u) {
                var brands = ['paypal','amazon','facebook','microsoft','apple','netflix','instagram','twitter','linkedin','whatsapp','bank','ebay'];
                try {
                    var parts = new URL(u).hostname.split('.');
                    if (parts.length < 3) return false;
                    var subdomain = parts.slice(0, parts.length - 2).join('.');
                    return brands.some(function(b) { return subdomain.indexOf(b) !== -1; });
                } catch(e) { return false; }
            }
        },
        {
            name: 'Deep URL Path',
            custom: function(u) {
                try { return new URL(u).pathname.split('/').length > 8; }
                catch(e) { return false; }
            }
        },
        {
            name: 'Number-Letter Substitution',
            custom: function(u) {
                var brands = ['paypal','amazon','google','facebook','microsoft','apple','netflix','instagram','twitter','linkedin','bank','ebay'];
                try {
                    var domain = new URL(u).hostname.toLowerCase();
                    var norm = domain.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s');
                    return brands.some(function(b) { return norm.indexOf(b) !== -1 && domain.indexOf(b) === -1; });
                } catch(e) { return false; }
            }
        },
        {
            name: '@ Symbol Trick',
            custom: function(u) {
                try { return new URL(u).username !== ''; }
                catch(e) { return false; }
            }
        },
        {
            name: 'Excessive Dots in Domain',
            custom: function(u) { return (getDomain(u).match(/\./g) || []).length >= 5; }
        },
        {
            name: 'Hex Encoded Characters',
            custom: function(u) {
                try {
                    var path = new URL(u).pathname + new URL(u).search;
                    return (path.match(/%[0-9a-fA-F]{2}/g) || []).length >= 5;
                } catch(e) { return false; }
            }
        },
        {
            name: 'Suspicious File Extension',
            custom: function(u) {
                return ['.exe','.bat','.cmd','.ps1','.vbs','.scr','.msi','.jar'].some(function(e) { return u.toLowerCase().indexOf(e) !== -1; });
            }
        },
        {
            name: 'Free Hosting Platform',
            custom: function(u) {
                return ['000webhostapp.com','weebly.com','wixsite.com','glitch.me','firebaseapp.com'].some(function(h) { return u.toLowerCase().indexOf(h) !== -1; });
            }
        },
        {
            name: 'Urgency Words',
            custom: function(u) {
                return ['account-suspended','account-locked','action-required','act-now','final-notice','verify-now','confirm-identity'].some(function(w) { return u.toLowerCase().indexOf(w) !== -1; });
            }
        },
        {
            name: 'Email Tracking Abuse',
            custom: function(u) {
                return ['sendgrid.net','ct.sendgrid','mailchimp.com','list-manage.com','mandrillapp.com','emltrk.com'].some(function(s) { return u.toLowerCase().indexOf(s) !== -1; });
            }
        },
        {
            name: 'Numeric Subdomain',
            custom: function(u) {
                try {
                    return new URL(u).hostname.split('.').some(function(p) { return /^[a-z]{0,2}\d{5,}$/.test(p); });
                } catch(e) { return false; }
            }
        },
        {
            name: 'Auto-Generated Domain',
            custom: function(u) {
                var domain = getDomain(u).split('.')[0];
                return /\d{5,}/.test(domain) || (/[a-z]\d{3,}/.test(domain) && domain.length > 8);
            }
        },
        {
            name: 'Encoded Hidden URL',
            custom: function(u) { return (u.match(/-2F|-2B|-3D|-2C|-3A/gi) || []).length >= 3; }
        },
        {
            name: 'Click Tracking Path',
            custom: function(u) {
                var paths = ['/ls/click','/track/click','/wf/click','/lt.php','/click.php'];
                try {
                    var pn = new URL(u).pathname.toLowerCase();
                    return paths.some(function(p) { return pn.indexOf(p) === 0; });
                } catch(e) { return false; }
            }
        },
        {
            name: 'SendGrid Redirect Abuse',
            custom: function(u) {
                var isTracking = ['sendgrid.net','ct.sendgrid','mailchimp.com','list-manage.com'].some(function(s) { return u.toLowerCase().indexOf(s) !== -1; });
                var isClick = false;
                try {
                    var pn = new URL(u).pathname.toLowerCase();
                    isClick = ['/ls/click','/click','/track/click'].some(function(p) { return pn.indexOf(p) === 0; });
                } catch(e) {}
                return isTracking && isClick;
            }
        },
        {
            name: 'Nested URL in Parameter',
            custom: function(u) {
                try {
                    var params = new URL(u).search;
                    return /upn=|url=|u=|link=/.test(params) && params.length > 50;
                } catch(e) { return false; }
            }
        },
        {
            name: 'Long Query String',
            custom: function(u) {
                try { return new URL(u).search.length > 200; }
                catch(e) { return false; }
            }
        },
        {
            name: 'Multiple Redirects',
            custom: function(u) {
                return ['redirect=','url=','next=','dest=','goto=','link=','target='].filter(function(p) { return u.toLowerCase().indexOf(p) !== -1; }).length >= 2;
            }
        },
        {
            name: 'Suspicious Redirect Parameter',
            custom: function(u) {
                try {
                    var params = new URL(u).search.toLowerCase();
                    return ['upn=','url=','link=','dest=','goto=','target=','redir='].some(function(p) { return params.indexOf(p) !== -1; }) && params.length > 100;
                } catch(e) { return false; }
            }
        }
    ];

    var vulnerable = 0;
    for (var i = 0; i < tests.length; i++) {
        try { if (tests[i].custom(url)) vulnerable++; } catch(e) {}
    }
    return { vulnerable: vulnerable, safe: tests.length - vulnerable, total: tests.length };
}

function removePopup() {
    var p = document.getElementById('lh-popup');
    if (p && p.parentNode) p.parentNode.removeChild(p);
}

function showPopup(href, clientX, clientY) {
    removePopup();

    var result = scanURL(href);
    var v = result.vulnerable;
    var color = v === 0 ? '#00d4ff' : v <= 2 ? '#ffcc00' : '#ff4d4d';
    var risk  = v === 0 ? '✅ SAFE' : v <= 2 ? '⚠️ MODERATE' : '🚨 HIGH RISK';

    var div = document.createElement('div');
    div.id = 'lh-popup';

    var top  = Math.min(clientY + 16, window.innerHeight - 110);
    var left = Math.min(clientX + 16, window.innerWidth  - 330);

    div.setAttribute('style',
        'all:unset !important;' +
        'display:block !important;' +
        'position:fixed !important;' +
        'top:'    + top  + 'px !important;' +
        'left:'   + left + 'px !important;' +
        'background:#1a1a2e !important;' +
        'color:#fff !important;' +
        'padding:10px 14px !important;' +
        'border-radius:8px !important;' +
        'z-index:2147483647 !important;' +
        'font-size:13px !important;' +
        'font-family:Arial,sans-serif !important;' +
        'border:2px solid ' + color + ' !important;' +
        'min-width:200px !important;' +
        'max-width:320px !important;' +
        'pointer-events:none !important;' +
        'box-shadow:0 4px 20px rgba(0,0,0,0.8) !important;' +
        'word-break:break-all !important;' +
        'line-height:1.5 !important;' +
        'visibility:visible !important;' +
        'opacity:1 !important'
    );

    var shortUrl = href.length > 45 ? href.slice(0, 45) + '...' : href;
    div.innerHTML =
        '<div style="font-size:10px;color:#aaa;margin-bottom:5px;">' + shortUrl + '</div>' +
        '<div style="font-size:15px;font-weight:bold;color:' + color + ';margin-bottom:3px;">' + risk + '</div>' +
        '<div style="font-size:11px;color:#ccc;">⚠️ ' + v + ' threats &nbsp;|&nbsp; ' + result.total + ' checks</div>';

    var container = document.body || document.documentElement;
    container.appendChild(div);
}

var currentHref = null;

document.addEventListener('mousemove', function(e) {
    var target = e.target;
    var link = null;
    var depth = 0;

    while (target && target !== document && depth < 15) {
        if (target.tagName === 'A') { link = target; break; }
        target = target.parentNode;
        depth++;
    }

    if (!link) {
        currentHref = null;
        removePopup();
        return;
    }

    var href = '';
    try {
        href = link.href || link.getAttribute('href') || '';
    } catch(ex) { return; }

    if (!href || href.indexOf('http') !== 0) {
        currentHref = null;
        removePopup();
        return;
    }

    if (href !== currentHref) {
        currentHref = href;
        showPopup(href, e.clientX, e.clientY);
    }

}, true); 

document.addEventListener('mouseleave', function() {
    currentHref = null;
    removePopup();
});
