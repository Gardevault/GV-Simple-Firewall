<?php
/*
Plugin Name: GV Simple Firewall
Description: Minimal WordPress request firewall. XML-RPC blocking, bad-UA filters, basic injection signatures, login/xmlrpc rate limits, optional HTTPS enforcement, lightweight file logging. Settings: Settings → GV Firewall.
Version: 0.5.1
Author: Gardevault
Update URI: false
*/



if (!defined('ABSPATH')) exit;

class GVFW {
    const OPT = 'gvfw_settings';
    const VER = '0.5.1';

    /* ---------- Bootstrap ---------- */
    public static function init() {
        add_action('plugins_loaded', [__CLASS__, 'maybe_activate_defaults'], 1);
        add_action('plugins_loaded', [__CLASS__, 'wire_admin'], 5);
        add_action('plugins_loaded', [__CLASS__, 'wire_runtime'], 0);

        // secure log download endpoint (cap-checked + nonce)
        add_action('admin_post_gvfw_download_log', [__CLASS__, 'handle_download_log']);
    }

    

    /* ---------- Defaults ---------- */
    public static function defaults() {
        return [
            'require_ssl'       => 0,
            'block_xmlrpc'      => 1,
            'remove_x_pingback' => 1,
            'bad_ua'            => 1,
            'sig_sql_xss'       => 1,
            'rl_login_n'        => 30,
            'rl_login_win'      => 600,
            'rl_xmlrpc_n'       => 30,
            'rl_xmlrpc_win'     => 600,
            'allowlist'         => '',
            'denylist'          => '',
            'log_enabled'       => 1,
            'log_days'          => 10,
        ];
    }

    public static function get() {
        return wp_parse_args(get_option(self::OPT, []), self::defaults());
    }

    public static function maybe_activate_defaults() {
        if (!get_option(self::OPT)) {
            add_option(self::OPT, self::defaults(), '', false);
        }
    }

    /* ---------- Admin UI ---------- */
    public static function wire_admin() {
        if (!is_admin()) return;

add_action('gv_core_register_module', function() {
  gv_core_register_module([
    'slug'=>'gvfw','name'=>'GV Simple Firewall',
    'version'=>defined('GVFW_VER')?GVFW_VER:'',
    'settings_url'=>admin_url('options-general.php?page=gvfw_settings'),
  ]);
  });
        add_action('admin_menu', function () {
            add_options_page('GV Firewall', 'GV Firewall', 'manage_options', self::OPT, [__CLASS__, 'render']);
        });

        // Tools page. Capability is filterable; default manage_options.
        add_action('admin_menu', function () {
            $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
            add_management_page('GV Firewall Logs', 'GV Firewall Logs', $cap, 'gvfw_logs', [__CLASS__, 'render_logs']);
        });

        add_action('admin_init', [__CLASS__, 'register']);

        // Add plugin action link
        // Note: __FILE__ must be relative to this file.
        $plugin_file = plugin_basename( __FILE__ ); 
        add_filter( 'plugin_action_links_' . $plugin_file, [__CLASS__, 'add_action_links'] );
    }

    public static function register() {
        register_setting(self::OPT, self::OPT, [__CLASS__, 'sanitize']);

        add_settings_section('gvfw_main', 'GV Simple Firewall', function () {
            echo '<p>Lightweight request filters and limits. Keep it simple.</p>';
        }, self::OPT);

        self::add_cb('require_ssl', 'Require HTTPS for login/admin');
        self::add_cb('block_xmlrpc', 'Block xmlrpc.php');
        self::add_cb('remove_x_pingback', 'Remove X-Pingback header');
        self::add_cb('bad_ua', 'Block basic bad user-agents');
        self::add_cb('sig_sql_xss', 'Block basic SQL/XSS signatures');

        self::add_num('rl_login_n', 'Login rate limit: attempts', 1, 1000);
        self::add_num('rl_login_win', 'Login window: seconds', 30, 3600);
        self::add_num('rl_xmlrpc_n', 'XML-RPC rate limit: attempts', 1, 1000);
        self::add_num('rl_xmlrpc_win', 'XML-RPC window: seconds', 30, 3600);

        add_settings_field('allowlist', 'Allowlist IPs/CIDR', function () {
            $o = self::get();
            printf('<input type="text" class="regular-text" name="%s[allowlist]" value="%s" placeholder="1.2.3.4, 10.0.0.0/8" />', esc_attr(self::OPT), esc_attr($o['allowlist']));
        }, self::OPT, 'gvfw_main');

        add_settings_field('denylist', 'Denylist IPs/CIDR', function () {
            $o = self::get();
            printf('<input type="text" class="regular-text" name="%s[denylist]" value="%s" placeholder="203.0.113.5, 192.0.2.0/24" />', esc_attr(self::OPT), esc_attr($o['denylist']));
        }, self::OPT, 'gvfw_main');

        self::add_cb('log_enabled', 'Enable lightweight file logging');
        self::add_num('log_days', 'Keep logs (days)', 1, 90);
    }

    private static function add_cb($key, $label) {
        add_settings_field($key, $label, function () use ($key) {
            $o = self::get();
            printf('<label><input type="checkbox" name="%s[%s]" value="1" %s> </label>', esc_attr(self::OPT), esc_attr($key), checked(!empty($o[$key]), 1, false));
        }, self::OPT, 'gvfw_main');
    }

    private static function add_num($key, $label, $min, $max) {
        add_settings_field($key, $label, function () use ($key, $min, $max) {
            $o = self::get();
            printf('<input type="number" name="%s[%s]" value="%d" min="%d" max="%d" />', esc_attr(self::OPT), esc_attr($key), intval($o[$key]), $min, $max);
        }, self::OPT, 'gvfw_main');
    }

    public static function sanitize($in) {
        $d = self::defaults(); $out = [];
        $out['require_ssl']       = !empty($in['require_ssl']) ? 1 : 0;
        $out['block_xmlrpc']      = !empty($in['block_xmlrpc']) ? 1 : 0;
        $out['remove_x_pingback'] = !empty($in['remove_x_pingback']) ? 1 : 0;
        $out['bad_ua']            = !empty($in['bad_ua']) ? 1 : 0;
        $out['sig_sql_xss']       = !empty($in['sig_sql_xss']) ? 1 : 0;
        $out['rl_login_n']        = max(1, intval($in['rl_login_n'] ?? $d['rl_login_n']));
        $out['rl_login_win']      = max(30, intval($in['rl_login_win'] ?? $d['rl_login_win']));
        $out['rl_xmlrpc_n']       = max(1, intval($in['rl_xmlrpc_n'] ?? $d['rl_xmlrpc_n']));
        $out['rl_xmlrpc_win']     = max(30, intval($in['rl_xmlrpc_win'] ?? $d['rl_xmlrpc_win']));
        // bound and sanitize long text inputs
        $out['allowlist']         = substr(sanitize_text_field($in['allowlist'] ?? ''), 0, 1000);
        $out['denylist']          = substr(sanitize_text_field($in['denylist']  ?? ''), 0, 1000);
        $out['log_enabled']       = !empty($in['log_enabled']) ? 1 : 0;
        $out['log_days']          = max(1, intval($in['log_days'] ?? $d['log_days']));
        return $out;
    }

    public static function render() {
    if (!current_user_can('manage_options')) return;

    // Use a two-column layout
    echo '<div class="wrap"><h1 style="margin-bottom: 15px;">GV Simple Firewall</h1>';
    echo '<div id="poststuff" style="display: grid; grid-template-columns: 2fr 1fr; grid-gap: 20px;">';

    // --- Column 1: Settings Form & Logs ---
    echo '<div id="post-body" class="postbox-container">';
        
        // Settings Box
        echo '<div class="postbox"><div class="inside">';
        echo '<h3>Plugin Settings</h3>';
        echo '<form method="post" action="options.php">';
        settings_fields(self::OPT);
        do_settings_sections(self::OPT);
        submit_button('Save settings');
        echo '</form>';
        echo '</div></div>'; // close .inside and .postbox

        // Log Download Box
        echo '<div class="postbox"><div class="inside">';
        echo '<h3>Download Logs</h3>';
        $latest = self::latest_log_path();
        if ($latest) {
            $url = wp_nonce_url(admin_url('admin-post.php?action=gvfw_download_log'), 'gvfw_download_log');
            printf('<p><a class="button" href="%s">Download latest log</a> <span class="description">(%s)</span></p>', esc_url($url), esc_html(basename($latest)));
        } else {
            echo '<p class="description">No log file yet.</p>';
        }
        echo '</div></div>'; // close .inside and .postbox
    
    echo '</div>'; // close column 1

    // --- Column 2: Gardevault Services (The "Bridge") ---
    echo '<div id="postbox-container-1" class="postbox-container">';
        echo '<div class="postbox">';
        echo '<h3 class="hndle" style="padding: 12px;"><span>Your Security Partner</span></h3>';
        echo '<div class="inside">';

        // --- MODIFICATION START ---
        // Use plugins_url() to get the correct URL from the plugin's folder
        $logo_url = plugins_url( 'assets/imgs/gardevault-logo.webp', __FILE__ );
        echo '<img src="' . esc_url( $logo_url ) . '" alt="Gardevault Logo" style="max-width: 150px; height: auto; margin: 0 auto 15px; display: block;">';
        // --- MODIFICATION END ---

        echo '<p>This plugin is proudly built by <strong>Gardevault</strong> to provide a simple, secure baseline.</p>';
        echo '<p><strong>Need expert help?</strong> We offer full-service security and development:</p>';
        echo '<ul style="list-style: disc; padding-left: 20px;">';
    
        echo '<li><a href="https://gardevault.eu/nfosec-consultation/" target="_blank">Professional Infosec Audits</a></li>';
    
        echo '<li><a href="https://gardevault.eu/web" target="_blank">Custom B2B Website Builds</a></li>';
        echo '</ul>';
        
        // --- MODIFICATION START (Fixed button text to match link) ---
        echo '<a href="https://gardevault.eu" target="_blank" class="button button-primary" style="width: 100%; text-align: center;">Visit Gardevault.eu</a>';
        // --- MODIFICATION END ---
        
        echo '</div>';
        echo '</div>'; // close .postbox
    echo '</div>'; // close column 2

    echo '</div>'; // close #poststuff
    echo '</div>'; // close .wrap
}



    public static function render_logs() {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) wp_die('Unauthorized', 403);
        echo '<div class="wrap"><h1>GV Firewall Logs</h1>';

        // --- START ADDITION ---
        echo '<div class="notice notice-info inline" style="margin-bottom: 15px; padding-top: 10px;">';
        echo '<p><strong>Seeing a lot of `sig-sql-xss` or `rate-login` blocks?</strong></p>';
        echo '<p>These logs show the firewall is working, but they can also indicate a targeted attack or a specific vulnerability. Our experts can perform a full <strong>infosec audit</strong> to find the root cause and permanently secure your site.</p>';
        echo '<p><a href="https://gardevault.com/security-audit" class="button button-primary" target="_blank">Get a Professional Gardevault Audit</a></p>';
        echo '</div>';
        // --- END ADDITION ---

        $latest = self::latest_log_path();
        if ($latest) {
            $url = wp_nonce_url(admin_url('admin-post.php?action=gvfw_download_log'), 'gvfw_download_log');
            printf('<p><a class="button button-primary" href="%s">Download latest log</a> <span class="description">(%s)</span></p>', esc_url($url), esc_html(basename($latest)));
        } else {
            echo '<p class="description">No log file yet.</p>';
        }
        echo '</div>';
    }

    public static function handle_download_log() {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) wp_die('Unauthorized', 403);
        if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'gvfw_download_log')) wp_die('Bad nonce', 403);

        $file = self::latest_log_path();
        if (!$file || !is_readable($file)) wp_die('No log available', 404);

        while (ob_get_level()) { ob_end_clean(); }
        header('Content-Type: text/plain');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }

    /* ---------- Runtime ---------- */
    public static function wire_runtime() {
        $o = self::get();

        if (!is_admin() && $o['remove_x_pingback']) {
            add_filter('wp_headers', function ($h) { unset($h['X-Pingback']); return $h; }, 99);
        }
        if ($o['block_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false', 99);
        }

        if ($o['require_ssl']) {
            add_action('init', function () {
                if (is_ssl()) return;
                if (self::is_sensitive_route()) {
                    $url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
                    wp_safe_redirect($url, 301);
                    exit;
                }
            }, 0);
        }

        add_action('init', [__CLASS__, 'gate'], 0);
    }

    public static function gate() {
        if (defined('WP_CLI') && WP_CLI) return;
        if (defined('DOING_CRON') && DOING_CRON) return;

        $o   = self::get();
        $ip  = self::client_ip();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($o['allowlist'] && self::ip_in_list($ip, $o['allowlist'])) return;
        if ($o['denylist'] && self::ip_in_list($ip, $o['denylist'])) self::block(403, 'denylist', $ip, $uri, $ua);

        if ($o['block_xmlrpc'] && self::is_xmlrpc()) self::block(403, 'xmlrpc-block', $ip, $uri, $ua);
        if ($o['bad_ua'] && self::is_bad_ua($ua)) self::block(403, 'bad-ua', $ip, $uri, $ua);
        if ($o['sig_sql_xss'] && self::trips_signatures()) self::block(403, 'sig-sql-xss', $ip, $uri, $ua);

        if (self::is_login())  self::rate_limit('login',  $o['rl_login_n'],  $o['rl_login_win']);
        if (self::is_xmlrpc()) self::rate_limit('xmlrpc', $o['rl_xmlrpc_n'], $o['rl_xmlrpc_win']);
    }

    /* ---------- Helpers: routes ---------- */
    private static function is_login() {
        $p = $_SERVER['SCRIPT_NAME'] ?? '';
        if (strpos($p, 'wp-login.php') !== false) return true;
        $req = $_SERVER['REQUEST_URI'] ?? '';
        return (strpos($req, '/wp-login.php') !== false);
    }

    private static function is_xmlrpc() {
        $p = $_SERVER['SCRIPT_NAME'] ?? '';
        if (strpos($p, 'xmlrpc.php') !== false) return true;
        $req = $_SERVER['REQUEST_URI'] ?? '';
        return (strpos($req, '/xmlrpc.php') !== false);
    }

    private static function is_sensitive_route() {
        if (self::is_login()) return true;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/wp-admin') === 0) return true;
        return false;
    }

    /* ---------- Helpers: IP and lists ---------- */
    private static function client_ip() {
        // default remote addr
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // optional proxy awareness
        $trusted = apply_filters('gvfw_trusted_proxies', []); // array of CIDRs
        $xff     = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff && !empty($trusted) && self::ip_in_any($ip, $trusted)) {
            $cand = trim(explode(',', $xff)[0]);
            if (filter_var($cand, FILTER_VALIDATE_IP)) $ip = $cand;
        }
        return $ip;
    }

    private static function ip_in_any($ip, $cidrs) {
        foreach ((array)$cidrs as $c) { if (self::cidr_match($ip, $c)) return true; }
        return false;
    }

    private static function ip_in_list($ip, $list_csv) {
        $items = array_filter(array_map('trim', explode(',', $list_csv)));
        foreach ($items as $item) {
            if ($item === $ip) return true;
            if (strpos($item, '/') !== false && self::cidr_match($ip, $item)) return true;
        }
        return false;
    }

    private static function cidr_match($ip, $cidr) {
        if (strpos($cidr, '/') === false) return false;
        list($subnet, $mask) = explode('/', $cidr, 2);
        $mask = (int)$mask;
        if ($mask < 0 || $mask > 32) return false;
        $ip_long = ip2long($ip);
        $sn_long = ip2long($subnet);
        if ($ip_long === false || $sn_long === false) return false;
        // 32-bit safe mask
        $m = ($mask === 0) ? 0 : ((-1 << (32 - $mask)) & 0xFFFFFFFF);
        return (($ip_long & $m) === ($sn_long & $m));
    }

    /* ---------- Helpers: UA and signatures ---------- */
    private static function is_bad_ua($ua) {
        if ($ua === '') return false;
        $ua = strtolower($ua);
        $bad = [
            'curl','wget','python-requests','httpclient','libwww-perl',
            'java/','okhttp','axios','scrapy','crawler','spider','nikto',
            'sqlmap','acunetix','nessus','dirbuster'
        ];
        foreach ($bad as $b) if (strpos($ua, $b) !== false) return true;
        return false;
    }

    private static function trips_signatures() {
        $q = $_SERVER['QUERY_STRING'] ?? '';
        $body = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $body = file_get_contents('php://input', false, null, 0, 4096);
        }
        $hay = strtolower(urldecode($q . '&' . $body));
        $re = [
            '/(?:\bunion\s+all\s+select|\bunion\s+select|\bload_file\s*\(|into\s+outfile)/i',
            '/(?:\bor\s+1=1\b|\band\s+1=1\b)/i',
            '/(?:<\s*script\b|javascript:|onerror\s*=|onload\s*=)/i',
            '/(?:\bupdatexml\s*\(|\bextractvalue\s*\()/i',
        ];
        foreach ($re as $rx) if (preg_match($rx, $hay)) return true;
        return false;
    }

    /* ---------- Rate limiting ---------- */
    private static function rate_limit($scope, $limit, $window) {
        $ip   = self::client_ip();
        $key  = 'gvfw_' . $scope . '_' . md5($ip);
        $now  = time();
        $buck = get_transient($key);
        if (!is_array($buck)) $buck = ['n' => 0, 'reset' => $now + $window];

        if ($now > $buck['reset']) $buck = ['n' => 0, 'reset' => $now + $window];
        $buck['n']++;
        set_transient($key, $buck, $buck['reset'] - $now);

        if ($buck['n'] > $limit) {
            self::block(429, "rate-$scope", $ip, ($_SERVER['REQUEST_URI'] ?? ''), ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        }
    }

    /* ---------- Block + log ---------- */
    private static function block($code, $reason, $ip, $uri, $ua) {
        status_header($code);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        header('X-GVFW: ' . $reason);
        self::log("$reason $code", $ip, $uri, $ua);
        echo "Request blocked ($reason).\n";
        exit;
    }

    private static function log($event, $ip, $uri, $ua) {
        $o = self::get();
        if (!$o['log_enabled']) return;

        $upload = wp_get_upload_dir();
        if (empty($upload['basedir'])) return;

        $dir = trailingslashit($upload['baseddir']) . 'gv-firewall';
        self::ensure_logs_dir_secure($dir);

        // bound values to prevent log injection and bloat
        $ua  = substr(str_replace(["\n", "\r"], ' ', (string)$ua), 0, 512);
        $uri = substr(str_replace(["\n", "\r"], ' ', (string)$uri), 0, 512);

        $file = $dir . '/gvf-' . gmdate('Y-m-d') . '.log';
        $line = sprintf("[%s] %s %s \"%s\" UA=\"%s\"\n",
            gmdate('c'), $ip, $event, $uri, $ua
        );

        $fh = @fopen($file, 'a');
        if ($fh) {
            @fwrite($fh, $line);
            @fclose($fh);
            @chmod($file, 0640);
        } else {
            @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
            @chmod($file, 0640);
        }

        self::prune_logs($dir, (int)$o['log_days']);
    }

    private static function ensure_logs_dir_secure($dir) {
        if (!is_dir($dir)) @wp_mkdir_p($dir);
        if (!file_exists("$dir/index.html")) @file_put_contents("$dir/index.html", "");
        // Apache hard-deny
        if (!file_exists("$dir/.htaccess")) {
            $ht = "Require all denied\nDeny from all\n";
            @file_put_contents("$dir/.htaccess", $ht);
        }
    }

    private static function prune_logs($dir, $days) {
        static $done = false; if ($done) return; $done = true;
        if (!is_dir($dir)) return;
        $cut = time() - ($days * 86400);
        foreach (glob($dir . '/gvf-*.log') as $f) {
            $mt = @filemtime($f);
            if ($mt !== false && $mt < $cut) @unlink($f);
        }
    }

    /* ---------- Logging helpers ---------- */
    private static function logs_dir() {
        $up = wp_get_upload_dir();
        return trailingslashit($up['basedir']) . 'gv-firewall';
    }

    private static function latest_log_path() {
        $dir = self::logs_dir();
        if (!is_dir($dir)) return false;
        $files = glob($dir . '/gvf-*.log');
        if (!$files) return false;
        rsort($files, SORT_NATURAL);
        return $files[0];
    }

    /**
     * Add custom links to the plugins page
     */
    public static function add_action_links( $links ) {
        $custom_links = [
            '<a href="https://gardevault.com/security-audit" target="_blank" style="color: #3db634; font-weight: bold;">Get Infosec Audit</a>'
        ];
        
        // Prepend new links
        return array_merge( $custom_links, $links );
    }

} // --- End of GVFW Class ---

GVFW::init();