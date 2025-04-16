import requests
import re
import argparse
from bs4 import BeautifulSoup

def supercharged_fingerprint(url):
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
        html = r.text.lower()
        soup = BeautifulSoup(html, 'html.parser')
        resp_headers = r.headers
        cookies = r.cookies
    except Exception as e:
        print(f"[ERROR] Couldn't fetch {url}: {e}")
        return

    tech = set()

    # Known HTML/JS patterns
    patterns = {
    # CMS
    'WordPress': r'wp-content|wp-includes',
    'Ghost': r'ghost\.org|ghost\/api|ghost-content',
    'Blogger': r'blogger\.com|blogspot\.com',
    'Webflow': r'webflow\.com|webflow\.js',
    'TYPO3': r'typo3|typo3conf',
    'Sitecore': r'sitecore|sc_analytics_',
    'Craft CMS': r'craftcms|craft\.js',
    'Duda': r'duda\.co|dudamobile\.com',
    'Weebly': r'weebly\.com|weeblycloud\.com',
    'Site123': r'site123\.com',
    'Tilda': r'tilda\.cc|tilda\.ws',
    'Cargo': r'cargocollective\.com',


    # Analytics
    'Google Tag Manager': r'googletagmanager\.com',
    'Google Tag Manager': r'googletagmanager\.com|gtm\.js',
    'Google Analytics': r'www\.google-analytics\.com|gtag\(\'config',
    'Matomo Analytics': r'matomo\.js|piwik\.js',
    'Plausible Analytics': r'plausible\.io/js',
    'Segment': r'segment\.com|analytics\.js|cdn\.segment\.com/analytics\.js',
    'Segment': r'segment\.com|cdn\.segment\.com|analytics\.js',
    'Hotjar': r'hotjar\.com|hotjar\.js',
    'Adobe Analytics': r'omniture|s\.code|sc\.js',
    'Heap Analytics': r'heap\.app|heap\.io|heap\.js',
    'Crazy Egg': r'crazyegg\.com|ce\.js',
    'Clicky': r'static\.getclicky\.com|in\.getclicky\.com',
    'Mixpanel': r'mixpanel\.com|mixpanel\.js',
    'Datadog': r'datadoghq\.com|datadog-browser-agent|dd\.js', 

    # Tag Managers
    'Tealium': r'tealiumiq\.com',
    'Optimizely': r'optimizely\.com|optimizely\.js',
    'Adobe Launch': r'adobedtm\.com|assets\.adobedtm\.com',

    # UI & Frontend
    'jQuery': r'jquery(\.min)?\.js',
    'Bootstrap': r'bootstrap(\.min)?\.(css|js)',
    'Tailwind CSS': r'tailwind(\.min)?\.css',
    'Font Awesome': r'fontawesome(\.min)?\.js',
    'Materialize CSS': r'materialize(\.min)?\.css',
    'UIKit': r'uikit(\.min)?\.css|uikit\.js',
    'Alpine.js': r'alpine(\.min)?\.js',
    'GSAP': r'gsap(\.min)?\.js',
    'Three.js': r'three(\.min)?\.js',
    'Chart.js': r'chart(\.min)?\.js',
    'Google Font API': r'fonts\.googleapis\.com|fonts\.gstatic\.com', 

    # Frameworks
    'React': r'react(\.min)?\.js|__reactinternalinstance|window\.__react',
    'Vue.js': r'vue(\.min)?\.js|window\.vue',
    'Angular': r'angular(\.min)?\.js|ng-version',
    'Svelte': r'svelte\.js',
    'Next.js': r'__next|window\.__next_data__',
    'Laravel': r'laravel_session|x-powered-by: laravel',
    'Express.js': r'x-powered-by: express',
    'Symfony': r'symfony|x-symfony-cache',
    'Spring Boot': r'springboot|x-spring-application',
    'Flask': r'x-powered-by: flask',

    # Platforms
    'Shopify': r'cdn\.shopify\.com|x-shopify-stage',
    'Magento': r'mage\/mage\.js|magento',
    'Drupal': r'drupal\.settings|drupal\.js|window\.drupalsettings',
    'Joomla': r'joomla',
    'Django': r'csrftoken|sessionid',
    'Rails': r'csrf-token|rails\.js',
    'Wix': r'wix\.com|wix-code',
    'Squarespace': r'squarespace\.com',
    'HubSpot': r'js\.hs-scripts\.com|hubspot\.com',
    'Facebook Pixel': r'connect\.facebook\.net|fbq\(',

    # DevOps / Monitoring
    'Sentry': r'sentry\.io|browser\.sentry-cdn\.com',
    'Rollbar': r'rollbar\.com|rollbar\.js',
    'New Relic': r'js-agent\.newrelic\.com',
    'Datadog': r'datadoghq\.com|datadog.*\.js',
    'StatusPage': r'statuspage\.io',
    'Pingdom': r'pingdom\.net|rum-static\.pingdom\.net',
    'Uptime Robot': r'uptimerobot\.com|uptimerobotapi',


    # Hosting / CDN
    'Cloudflare': r'cloudflareinsights\.com|cloudflare\.com',
    'Netlify': r'netlify\.app|netlify\.com',
    'Vercel': r'vercel\.app|vercel\.com',
    'Amazon CloudFront': r'cloudfront\.net',
    'Azure': r'azureedge\.net|azurewebsites\.net',
    'DigitalOcean': r'digitaloceanspaces\.com',
    'Fastly': r'fastly\.net|fastly-ssl\.com',
    'Akamai': r'akamai\.net|akamaized\.net',
    'Firebase Hosting': r'firebaseapp\.com',

    # Security
    'reCAPTCHA': r'www\.google\.com/recaptcha',
    'Sucuri': r'sucuri\.net|sucuri_firewall',
    'Imperva': r'incapsula\.com|x-cdn',
    'HSTS': r'strict-transport-security', 

    # Microsoft
    'Microsoft ASP.NET': r'asp\.net|x-aspnet-version',

    # E-commerce Platforms
    'BigCommerce': r'bigcommerce\.com|bigcommerce\.js',
    'WooCommerce': r'woocommerce\.js|wp-content/plugins/woocommerce',
    'PrestaShop': r'prestashop\.com|prestashop\.js',
    'OpenCart': r'opencart\.com|catalog/view/theme',
    'ZenCart': r'zencart\.com|zc_install',
    'osCommerce': r'oscommerce\.com|catalog/includes',

    # Payment Platforms
    'PayPal': r'paypal\.com|paypal\.js',
    'Stripe': r'stripe\.com|stripe\.js',
    'Square': r'square\.com|squareup\.com',
    'Razorpay': r'razorpay\.com|razorpay\.js',
    'Authorize.Net': r'secure.authorize.net|anet\.js',
    'Adyen': r'adyen\.com|adyen\.js',

    # Content Delivery Networks (CDNs)
    'Cloudflare': r'cloudflare\.com|cloudflare\.insights',
    'Akamai': r'akamai\.net|akamaized\.net',
    'Fastly': r'fastly\.net|fastly-ssl\.com',
    'AWS CloudFront': r'cloudfront\.net|d2r1v16n6sby0p.cloudfront.net',
    'CDN77': r'cdn77\.com',
    'KeyCDN': r'keycdn\.com',

    # Analytics/Tracking Platforms
    'Mixpanel': r'mixpanel\.com|mixpanel\.js',
    'Kissmetrics': r'kissmetrics\.com|kissmetrics\.js',
    'Intercom': r'intercom\.com|widget\.js',
    'Zendesk': r'zendesk\.com|zendesk\.js',
    'Pendo': r'pendo\.io|pendo\.js',
    'FullStory': r'fullstory\.com|fullstory\.js',
    'Optimizely': r'optimizely\.com|optimizely\.js',
    'Amplitude': r'amplitude\.com|amplitude\.js',

    # Web Frameworks
    'Laravel': r'laravel\.com|laravel_session',
    'Django': r'django\.com|csrftoken',
    'Flask': r'flask\.com|flask-session',
    'Ruby on Rails': r'rails\.com|csrf-token',
    'Ruby on Rails': r'rails\.js|csrf-token|x-rack-cache',
    'Spring Boot': r'springboot\.com|x-spring-application',
    'ASP.NET': r'asp\.net|x-aspnet-version',

    # UI Libraries & Frameworks
    'React': r'react\.js|window\.__react',
    'Vue.js': r'vue\.js|window\.vue',
    'AngularJS': r'angular\.js|ng-version',
    'Svelte': r'svelte\.js',
    'Ember.js': r'ember\.js',
    'Backbone.js': r'backbone\.js',

    #Marketing Automation
    'ActiveCampaign': r'activecampaign\.com|trackcmp\.net',
    'Iterable': r'iterable\.com|iterable\.js',
    'AutopilotHQ': r'autopilothq\.com|autopilot\.js',
    'Customer.io': r'customer\.io|customerio\.js',

    #Feature Flag & Experimentation Tools
    'LaunchDarkly': r'launchdarkly\.com|ldclient\.js',
    'Split.io': r'split\.io|cdn\.split\.io',
    'Flagsmith': r'flagsmith\.com|flagsmith\.js',

    #CRM & Sales Tools
    'Salesforce': r'salesforce\.com|force\.com',
    'Zoho CRM': r'zoho\.com/crm|crm\.zoho\.com',
    'Freshsales': r'freshsales\.io|freshworks\.com',
    'Pipedrive': r'pipedrive\.com|pipedrivecdn\.com',

    #Ad Tech / Retargeting / Pixels
    'Criteo': r'criteo\.com|criteo\.net',
    'Taboola': r'taboola\.com|trc\.taboola\.com',
    'Outbrain': r'outbrain\.com|widgets\.outbrain\.com',
    'AdRoll': r'adroll\.com|s\.adroll\.com',
    'DoubleClick': r'doubleclick\.net',

    #Search / Recommendation / Personalization
    'Algolia': r'algolia\.net|algolia\.com',
    'Searchspring': r'searchspring\.net|searchspring\.com',
    'Constructor.io': r'constructor\.io|constructorio\.com',
    'Clerk.io': r'clerk\.io|clerkcdn\.com',
    'Demandbase': r'demandbase\.com|demandbase\.js',
    'PWA': r'serviceWorker\.register|manifest\.json',
    'Open Graph': r'og:|property="og:',
    'Prism': r'prism(\.min)?\.js',
    'PyScript': r'pyscript\.js|pyscript\.css',


    #Headless CMS / Content APIs
    'Contentful': r'contentful\.com|cdn\.contentful\.com',
    'Sanity': r'sanity\.io|cdn\.sanity\.io',
    'Strapi': r'strapi\.io|strapi',
    'Prismic': r'prismic\.io|cdn\.prismic\.io',

    #Authentication / Identity Management
    'Auth0': r'auth0\.com|cdn\.auth0\.com',
    'Okta': r'okta\.com|oktaauth\.js',
    'Firebase Auth': r'firebaseio\.com|auth\.firebase',
    'Keycloak': r'keycloak\.org|auth/realms',

    #Video / Multimedia Embeds
    'Wistia': r'wistia\.com|fast\.wistia\.com',
    'Vimeo': r'vimeo\.com|player\.vimeo\.com',
    'JW Player': r'jwplayer\.com|jwplayer\.js',
    'Brightcove': r'brightcove\.net|brightcove\.com',

    # JavaScript Libraries
    'jQuery': r'jquery\.js',
    'Moment.js': r'moment\.js',
    'Lodash': r'lodash\.js',
    'Dropzone': r'dropzone(\.min)?\.js',
    'core-js': r'core-js(\.min)?\.js',
    'Underscore.js': r'underscore\.js',
    'Chart.js': r'chart\.js',
    'Axios': r'axios(\.min)?\.js',
    'RxJS': r'rxjs(\.min)?\.js',
    'Anime.js': r'anime(\.min)?\.js',
    'D3.js': r'd3(\.min)?\.js',
    'Hammer.js': r'hammer(\.min)?\.js',
    'Leaflet': r'leaflet(\.min)?\.js',
    'Clipboard.js': r'clipboard(\.min)?\.js',
    'Popper.js': r'popper(\.min)?\.js',
    'Goober': r'goober(\.min)?\.js',
    'FingerprintJS': r'fp\.js|fingerprintjs(\.min)?\.js',
    'FingerprintJS': r'fingerprintjs(\.min)?\.js',




    # Social Media/Advertising
    'Facebook Pixel': r'connect\.facebook\.net|fbq\(',
    'Twitter Analytics': r'twitter\.com|twitpic\.com',
    'Google Ads': r'googleads\.g\.com|ads\.google\.com',
    'LinkedIn Insights': r'linkedin\.com|snap\.linkedin\.com',
    'Snapchat Pixel': r'sc-static\.net|snap\.snapchat\.com',
    'Pinterest Tag': r'ct\.pinterest\.com|pinimg\.com',
    'TikTok Pixel': r'tiktok\.com|analytics\.tiktok\.com',
    'Reddit Pixel': r'reddit\.com|alb\.reddit\.com',
    'Quora Pixel': r'qquora\.com|quora\.js',
    'TikTok Pixel': r'analytics\.tiktok\.com|tiktok\.com/pixel',
    'Microsoft Clarity': r'clarity\.ms|clarity\.js',
    'GA4': r'gtag\("config",\s*"G-[A-Z0-9]+"\)',
    'theTradeDesk': r'ttd\.com|adsrvr\.org',
    'Twitter Ads': r'ads\.twitter\.com|analytics\.twitter\.com',
    'Reddit Ads': r'reddit\.com/ads|alb\.reddit\.com',
    'Microsoft Advertising': r'bingads\.microsoft\.com|bat\.bing\.com',

    #Web Servers
    'Kestrel': r'server: Kestrel',
    'Apache': r'server: Apache',
    'Nginx': r'server: nginx',
    'IIS': r'server: Microsoft-IIS',
    'Lighttpd': r'server: lighttpd',
    'Cloudflare': r'server: Cloudflare',
    'AWS Elastic Beanstalk': r'server: Elastic Beanstalk',

    

    # Cloud Platforms
    'AWS': r'aws\.amazon\.com|s3\.amazonaws\.com',
    'Google Cloud': r'googleapis\.com|googleusercontent\.com',
    'Microsoft Azure': r'azure\.com|azurewebsites\.net',
    'IBM Cloud': r'ibm\.com/cloud',
    'Heroku': r'herokuapp\.com',
    'Oracle Cloud': r'oraclecloud\.com|oracle\.com/cloud',
    'Linode': r'linode\.com',
    'Vultr': r'vultr\.com',
    'Amazon Web Services': r's3\.amazonaws\.com|aws\.amazon\.com',
    'Amazon S3': r's3\.amazonaws\.com|amazonaws\.com/s3', 



    # Web Security Tools
    'Sucuri': r'sucuri\.net|sucuri_firewall',
    'Incapsula': r'incapsula\.com|x-cdn',
    'Cloudflare': r'cloudflare\.com|cf\_clearance',
    'reCAPTCHA': r'www\.google\.com/recaptcha|recaptcha',
    'PerimeterX': r'px\.perimeterx\.net|px\.perimeterx\.com',
    'CloudArmor': r'cloudarmor\.googleapis\.com',
    'AWS WAF': r'waf\.amazonaws\.com',
    'Radware': r'radware\.com',


    # Other JavaScript Libraries
    'GSAP (GreenSock Animation Platform)': r'gsap\.js',
    'Three.js': r'three\.js',
    'Pixi.js': r'pixi\.js',
    'Socket.IO': r'socket\.io',
    'WebSocket': r'websocket',

    # Email Services
    'Mailchimp': r'mailchimp\.com|mc\.js',
    'SendGrid': r'sendgrid\.com|sendgrid\.js',
    'Mandrill': r'mandrillapp\.com|mandrill\.js',
    'Postmark': r'postmarkapp\.com|postmark\.js',
    'Mailgun': r'mailgun\.com|mailgun\.js',

    # Others
    'Typeform': r'typeform\.com|typeform\.js',
    'SurveyMonkey': r'surveymonkey\.com|sm\.js',
    'Zapier': r'zapier\.com|zapier\.js',
    'Trello': r'trello\.com|trello\.js',

    #A/B Testing & Personalization
    'Convert': r'cdn\.convert\.com',
    'Convert': r'cdn\.cnvrt\.co|convert\.com|convert\.js',
    'VWO': r'd2oh4tlt9mrke9\.cloudfront\.net|dev.visualwebsiteoptimizer\.com',
    'Adobe Target': r'mbox\.js|tt\.omtrdc\.net',

    #Additional Analytics / User Behavior
    'Crazy Egg': r'crazyegg\.com|script\.crazyegg\.com',
    'LogRocket': r'cdn\.logrocket\.io|logrocket\.com',
    'Mouseflow': r'mouseflow\.com|mouseflow\.js',
    'Lucky Orange': r'luckyorange\.com|lo\.js',

    #Live Chat & Messaging
    'Tawk.to': r'tawk\.to|embed\.tawk\.to',
    'LiveChat': r'livechatinc\.com|cdn\.livechatinc\.com',
    'Crisp Chat': r'crisp\.chat|client\.crisp\.chat',
    'Drift': r'drift\.com|drift\.js',
    'HubSpot Chat': r'hubspot\.com/livechat|js\.hs-scripts\.com',
    'Intercom': r'intercom\.com|widget\.intercom\.io|intercom\.js',


    #More E-commerce Tools
    'Shogun': r'shogun\.page|shgtrk',
    'Klaviyo': r'klaviyo\.com|klaviyo\.js',
    'Bold Commerce': r'boldapps\.net|boldcommerce',
    'Yotpo': r'yotpo\.com|staticw2\.yotpo\.com',
    'Astro': r'astro\.build|astro\.js',


    #Security / CAPTCHA / Bot Protection
    'Datadome': r'datadome\.co|js\.datadome\.co',
    'PerimeterX': r'px\.perimeterx\.net|captcha\.perimeterx\.net',
    'Arkose Labs': r'funcaptcha\.com|arkoselabs\.com',

    #Performance & Speed Tools
    'Google PageSpeed': r'pagespeed\.js',
    'LazySizes': r'lazysizes(\.min)?\.js',
    'Lozad.js': r'lozad(\.min)?\.js',

    #JavaScript Framework Utilities
    'Redux': r'redux(\.min)?\.js|window\.__REDUX_DEVTOOLS_EXTENSION__',
    'RxJS': r'rxjs(\.min)?\.js',
    'Immer': r'immer(\.min)?\.js',
    'styled-components': r'styled-components(\.min)?\.js',
    'Emotion': r'@emotion|emotion(-server|-react|-styled)?(\.min)?\.js',

    #Widget & Form Builders
    'JotForm': r'jotform\.com|jotform\.js',
    'Paperform': r'paperform\.co|paperform\.js',
    'Formstack': r'formstack\.com|formstack\.js',

    #Push Notifications / Customer Engagement
    'OneSignal': r'onesignal\.com|cdn\.onesignal\.com',
    'PushEngage': r'pushengage\.com|cdn\.pushengage\.com',
    'WebEngage': r'webengage\.com|cdn\.webengage\.com',

    #CDN / DNS / Hosting (More providers)
    'BunnyCDN': r'b-cdn\.net|bunnycdn\.com',
    'StackPath': r'stackpathcdn\.com|stackpath\.com',
    'Leaseweb': r'leasewebcdn\.com',
    'jsDelivr': r'cdn\.jsdelivr\.net', 

    }


    # Check HTML for patterns
    for tech_name, pattern in patterns.items():
        if re.search(pattern, html):
            tech.add(tech_name)

    # Meta tag analysis
    for meta in soup.find_all('meta'):
        name = meta.get('name', '').lower()
        content = meta.get('content', '').lower()
        if 'generator' in name or 'generator' in content:
            if 'wordpress' in content:
                tech.add('WordPress (meta tag)')
            elif 'joomla' in content:
                tech.add('Joomla (meta tag)')
            elif 'drupal' in content:
                tech.add('Drupal (meta tag)')
            elif 'shopify' in content:
                tech.add('Shopify (meta tag)')
        if 'viewport' in name and 'initial-scale' in content:
            tech.add('Responsive Design (meta viewport)')

    # Script & link tag analysis
    for tag in soup.find_all(['script', 'link']):
        src = tag.get('src') or tag.get('href') or ''
        for tech_name, pattern in patterns.items():
            if re.search(pattern, src):
                tech.add(tech_name)

    # Inline JS variables
    inline_js_vars = {
        'Next.js': '__next_data__',
        'Drupal': 'drupalSettings',
        'React': '__REACT_DEVTOOLS_GLOBAL_HOOK__',
        'Vue.js': 'Vue.config',
        'Shopify': 'Shopify.shop'
    }
    for script in soup.find_all('script'):
        script_content = script.string or ''
        for tech_name, keyword in inline_js_vars.items():
            if keyword.lower() in script_content.lower():
                tech.add(f'{tech_name} (inline JS)')

    # Cookie analysis
    for c in cookies:
        name = c.name.lower()
        if '_ga' in name:
            tech.add('Google Analytics (cookie)')
        elif '_gid' in name:
            tech.add('Google Analytics (_gid cookie)')
        elif '_fbp' in name:
            tech.add('Facebook Pixel (cookie)')
        elif '__cfduid' in name:
            tech.add('Cloudflare (cookie)')
        elif 'shopify' in name:
            tech.add('Shopify (cookie)')
        elif '__hstc' in name or 'hubspotutk' in name:
            tech.add('HubSpot (cookie)')
        elif 'ajs_anonymous_id' in name:
            tech.add('Segment (cookie)')
        elif 'intercom-session' in name:
            tech.add('Intercom (cookie)')
        elif '_hj' in name:
            tech.add('Hotjar (cookie)')
        elif '_mkto_trk' in name:
            tech.add('Marketo (cookie)')

    # HTTP Headers
    powered = resp_headers.get('x-powered-by', '').lower()
    if powered:
        tech.add(f"Powered by: {powered}")
    server = resp_headers.get('server', '').lower()
    if server:
        tech.add(f"Server: {server}")
    if 'x-aspnet-version' in resp_headers:
        tech.add('Microsoft ASP.NET (header)')

    # Output
    print(f"\n🔍 Detected technologies for {url}:\n")
    print(f"By Simar Randhawa\n")
    if tech:
        for t in sorted(tech):
            print("✅", t)
    else:
        print("❌ No recognizable technologies found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect web technologies used on a website.")
    parser.add_argument("url", help="The URL of the website to fingerprint.")
    args = parser.parse_args()

    supercharged_fingerprint(args.url)

# python info.py https://www.google.com
# By Simar Randhawa
