<?php
/*
Plugin Name: GV Simple Firewall
Description: Minimal WordPress request firewall. XML-RPC blocking, bad-UA filters, basic injection signatures, login/xmlrpc rate limits, optional HTTPS enforcement, lightweight file logging. Settings: Settings → GV Firewall.
Version: 1.1
Author: GardeVault
Update URI: false
Author URI: https://gardevault.eu
Plugin URI: https://gardevault.eu/plugins/gv-simple-firewall
*/

if (!defined('ABSPATH')) exit;

class GVFW {
    const OPT = 'gvfw_settings';
    const VER = '1.1';

    /* ---------- Bootstrap ---------- */
    public static function init() {
        add_action('plugins_loaded', [__CLASS__, 'maybe_activate_defaults'], 1);
        add_action('plugins_loaded', [__CLASS__, 'wire_admin'], 5);
        add_action('plugins_loaded', [__CLASS__, 'wire_runtime'], 0);
        add_action('wp_login', [__CLASS__, 'on_login'], 10, 2);
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed'], 10, 1);

        // secure log download endpoint (cap-checked + nonce)
        add_action('admin_post_gvfw_download_log', [__CLASS__, 'handle_download_log']);
    }

    public static function on_login($user_login, $user) {
        $o = self::get();
        if (empty($o['log_logins'])) return;
        $ip = self::client_ip();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        self::log('login-ok 200', $ip, '/wp-login.php', $ua, ['UN' => $user_login]);
    }

    public static function on_login_failed($username) {
        $o = self::get();
        if (empty($o['log_logins'])) return;
        $ip = self::client_ip();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        self::log('login-fail 401', $ip, '/wp-login.php', $ua, ['UN' => (string)$username]);
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
            'log_logins'        => 1,
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

        // Admin CSS, page-scoped (enqueue on Settings and Tools pages)
add_action('admin_enqueue_scripts', function ($hook) {
    // Apply CSS on any GV page (settings, tools, or the custom top-level page)
    if (strpos($hook, 'gvfw') !== false || strpos($hook, 'gardevault') !== false) {
        wp_enqueue_style(
            'gvfw-admin',
            plugins_url('assets/admin.css', __FILE__),
            [],
            GVFW::VER
        );
    }
});
        // Optional GV Core registration if present
        add_action('gv_core_register_module', function () {
// If GV Core exposes a function, call it directly.
// Otherwise, listen for its action and register when it fires.
if (function_exists('gv_core_register_module')) {
    gv_core_register_module([
        'slug'=>'gvfw','name'=>'GV Simple Firewall','version'=>self::VER,
        'settings_url'=>admin_url('options-general.php?page=' . self::OPT),
    ]);
} else {
    add_action('gv_core_register_module', function () {
        if (function_exists('gv_core_register_module')) {
            gv_core_register_module([
                'slug'=>'gvfw','name'=>'GV Simple Firewall','version'=>self::VER,
                'settings_url'=>admin_url('options-general.php?page=' . self::OPT),
            ]);
        }
    });
}

        });

// Top-level "GV Firewall" always. No submenus under GardeVault.
add_action('admin_menu', function () {
    $cap = 'manage_options';
    $slug = 'gvfw';

    add_menu_page(
        'GV Simple Firewall',
        'GV Firewall',
        $cap,
        $slug,
        [__CLASS__, 'render'],
        'dashicons-shield-alt',
        59
    );

    // Logs remain in Tools
    $cap_logs = apply_filters('gvfw_view_logs_cap', 'manage_options');
    add_management_page('GV Firewall Logs', 'GV Firewall Logs', $cap_logs, 'gvfw_logs', [__CLASS__, 'render_logs']);
}, 9);







        add_action('admin_init', [__CLASS__, 'register']);

        // Add plugin action link
        $plugin_file = plugin_basename(__FILE__);
        add_filter('plugin_action_links_' . $plugin_file, [__CLASS__, 'add_action_links']);
    }

    public static function register() {
        register_setting(self::OPT, self::OPT, [__CLASS__, 'sanitize']);
    }

    public static function sanitize($in) {
        $d = self::defaults(); $out = [];
        $out['log_logins']        = !empty($in['log_logins']) ? 1 : 0;
        $out['require_ssl']       = !empty($in['require_ssl']) ? 1 : 0;
        $out['block_xmlrpc']      = !empty($in['block_xmlrpc']) ? 1 : 0;
        $out['remove_x_pingback'] = !empty($in['remove_x_pingback']) ? 1 : 0;
        $out['bad_ua']            = !empty($in['bad_ua']) ? 1 : 0;
        $out['sig_sql_xss']       = !empty($in['sig_sql_xss']) ? 1 : 0;
        $out['rl_login_n']        = max(1, intval($in['rl_login_n'] ?? $d['rl_login_n']));
        $out['rl_login_win']      = max(30, intval($in['rl_login_win'] ?? $d['rl_login_win']));
        $out['rl_xmlrpc_n']       = max(1, intval($in['rl_xmlrpc_n'] ?? $d['rl_xmlrpc_n']));
        $out['rl_xmlrpc_win']     = max(30, intval($in['rl_xmlrpc_win'] ?? $d['rl_xmlrpc_win']));
        $out['allowlist']         = substr(sanitize_text_field($in['allowlist'] ?? ''), 0, 1000);
        $out['denylist']          = substr(sanitize_text_field($in['denylist']  ?? ''), 0, 1000);
        $out['log_enabled']       = !empty($in['log_enabled']) ? 1 : 0;
        $out['log_days']          = max(1, intval($in['log_days'] ?? $d['log_days']));
        return $out;
    }

    public static function render() {
        if (!current_user_can('manage_options')) return;
        $o = self::get();

        // quick stats
        $protections_on = (int)$o['require_ssl'] + (int)$o['block_xmlrpc'] + (int)$o['remove_x_pingback'] + (int)$o['bad_ua'] + (int)$o['sig_sql_xss'];
        $logging_on     = (int)$o['log_enabled'];

        echo '<div class="wrap gvfw-wrap">';
        echo '<div class="gvfw-header">';
        echo '<h1 class="gvfw-h1">GV Simple Firewall</h1>';
        echo '<div class="gvfw-chips">';
        if (!class_exists('GV_Core')) {
    echo '<div class="gvfw-cta" style="margin:.5rem 0 0;">';
    echo '<a class="button button-primary" href="https://gardevault.eu/plugins/gv-core/" target="_blank" rel="noopener">Download GV Core</a> ';
    echo '<a class="button" href="https://github.com/Davekrush/GV-Core-plugin" target="_blank" rel="noopener">View on GitHub</a>';
    echo '</div>';
}
        printf('<span class="gvfw-chip">%d protections on</span>', $protections_on);
        printf('<span class="gvfw-chip %s">logging %s</span>', $logging_on ? 'is-on' : 'is-off', $logging_on ? 'enabled' : 'disabled');
        printf('<span class="gvfw-chip mute">v%s</span>', esc_html(self::VER));
        echo '</div></div>';

        echo '<div class="gvfw-grid">';

        /* -------- LEFT: settings -------- */
        echo '<div class="gvfw-col">';
        echo '<form method="post" action="options.php" class="gvfw-form">';
        settings_fields(self::OPT);

        // Protection
        echo '<section class="gvfw-card"><h2>Protection</h2><div class="gvfw-fields gvfw-2col">';
        self::checkbox_row('Require HTTPS for login/admin', 'require_ssl', $o['require_ssl']);
        self::checkbox_row('Block xmlrpc.php', 'block_xmlrpc', $o['block_xmlrpc']);
        self::checkbox_row('Remove X-Pingback header', 'remove_x_pingback', $o['remove_x_pingback']);
        self::checkbox_row('Block basic bad user-agents', 'bad_ua', $o['bad_ua']);
        self::checkbox_row('Block basic SQL/XSS signatures', 'sig_sql_xss', $o['sig_sql_xss']);
        echo '</div></section>';

        // Rate limits
        echo '<section class="gvfw-card"><h2>Rate limits</h2><div class="gvfw-fields gvfw-4col">';
        self::number_row('Login attempts', 'rl_login_n', $o['rl_login_n'], 1, 1000);
        self::number_row('Login window (s)', 'rl_login_win', $o['rl_login_win'], 30, 3600);
        self::number_row('XML-RPC attempts', 'rl_xmlrpc_n', $o['rl_xmlrpc_n'], 1, 1000);
        self::number_row('XML-RPC window (s)', 'rl_xmlrpc_win', $o['rl_xmlrpc_win'], 30, 3600);
        echo '</div></section>';

        // IP control
        echo '<section class="gvfw-card"><h2>IP control</h2><div class="gvfw-fields">';
        self::text_row('Allowlist IPs/CIDR', 'allowlist', $o['allowlist'], '1.2.3.4, 10.0.0.0/8');
        self::text_row('Denylist IPs/CIDR', 'denylist', $o['denylist'], '203.0.113.5, 192.0.2.0/24');
        echo '</div></section>';

        // Logging
        echo '<section class="gvfw-card"><h2>Logging</h2><div class="gvfw-fields gvfw-2col">';
        self::checkbox_row('Enable lightweight file logging', 'log_enabled', $o['log_enabled']);
        self::number_row('Keep logs (days)', 'log_days', $o['log_days'], 1, 90);
        self::checkbox_row('Log successful/failed logins', 'log_logins', $o['log_logins']);
        echo '</div>';

        // Download latest
        $latest = self::latest_log_path();
        echo '<div class="gvfw-inline">';
        if ($latest) {
            $url = wp_nonce_url(admin_url('admin-post.php?action=gvfw_download_log'), 'gvfw_download_log');
            printf('<a class="button button-secondary" href="%s">Download latest log (%s)</a>',
                esc_url($url), esc_html(basename($latest)));
        } else {
            echo '<span class="description">No log file yet.</span>';
        }
        echo '</div></section>';

        // sticky save
        echo '<div class="gvfw-sticky">';
        submit_button('Save settings', 'primary', 'submit', false);
        echo '</div>';

        echo '</form>';
        echo '</div>'; // /left

        /* -------- RIGHT: recent log + support drawer -------- */
        echo '<aside class="gvfw-col gvfw-aside">';

        // Recent blocks panel
        echo '<div class="gvfw-card">';
        echo '<h2>Recent blocks</h2>';
        echo self::recent_log_block(50);
        echo '</div>';

        // Recent logins panel
        echo '<div class="gvfw-card">';
        echo '<h2>Recent logins</h2>';
        echo self::recent_login_block(50);
        echo '</div>';

        // Compact services drawer
        echo '<div class="gvfw-card gvfw-mini">';
        echo '<details class="gvfw-drawer">';
        echo '<summary><span class="gvfw-sum-title">Support & services</span></summary>';
        $logo_url = plugins_url('assets/imgs/gardevault-logo.webp', __FILE__);
        echo '<div class="gvfw-drawer-body">';
        echo '<img class="gvfw-logo" src="' . esc_url($logo_url) . '" alt="GardeVault logo">';
        echo '<p>Need a deeper audit or hardened build?</p>';
        echo '<ul class="gvfw-links">';
        echo '<li><a href="https://gardevault.eu/" target="_blank">Infosec audits</a></li>';
        echo '<li><a href="https://gardevault.eu/web" target="_blank">Secure B2B sites</a></li>';
        echo '</ul>';
        echo '<a href="https://gardevault.eu" target="_blank" class="button button-primary gvfw-wide">Visit GardeVault.eu</a>';
        echo '</div>';
        echo '</details>';
        echo '</div>';

        echo '</aside>';

        echo '</div>'; // /grid

        // footer toolbar
        echo '<div class="gvfw-toolbar">';
        echo '<span>GV Simple Firewall</span>';
        echo '<a href="https://gardevault.eu/plugins/gv-simple-firewall" target="_blank">Docs</a>';
        echo '<a href="https://gardevault.eu/contact" target="_blank">Contact</a>';
        echo '</div>';

        echo '</div>'; // /wrap
    }

    /* --- small helpers for custom form --- */
    private static function checkbox_row($label, $key, $checked) {
        printf(
            '<label class="gvfw-row gvfw-check"><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s><span>%4$s</span></label>',
            esc_attr(self::OPT), esc_attr($key), checked(!empty($checked), 1, false), esc_html($label)
        );
    }

    private static function number_row($label, $key, $value, $min, $max) {
        printf(
            '<label class="gvfw-row"><span class="gvfw-l">%1$s</span><input class="small-text" type="number" name="%2$s[%3$s]" value="%4$d" min="%5$d" max="%6$d"></label>',
            esc_html($label), esc_attr(self::OPT), esc_attr($key), intval($value), $min, $max
        );
    }

    private static function text_row($label, $key, $value, $ph='') {
        printf(
            '<label class="gvfw-row"><span class="gvfw-l">%1$s</span><input type="text" class="regular-text" name="%2$s[%3$s]" value="%4$s" placeholder="%5$s"></label>',
            esc_html($label), esc_attr(self::OPT), esc_attr($key), esc_attr($value), esc_attr($ph)
        );
    }

    /* ---------- Recent log widget (no inline CSS) ---------- */
    private static function recent_log_block($n = 50) {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) return '<p class="description">No permission to view logs.</p>';

        $latest = self::latest_log_path();
        if (!$latest) return '<p class="description">No log file yet.</p>';

        $lines = self::tail_file($latest, max(1, (int)$n), 256 * 1024);
        if (!$lines) return '<p class="description">No recent entries.</p>';

        $rows = '';
        foreach ($lines as $ln) {
            $e = self::parse_log_line($ln);
            if (!$e) continue;
            if (strpos($e['reason'], 'login-') === 0) continue; // exclude logins

            $badgeClass = ($e['code'] == 429) ? 'warn' : 'block';
            $friendly   = self::friendly_reason($e['reason']);

            $rows .= '<tr class="gvfw-logrow">'
                . '<td class="gvfw-logtime" title="' . esc_attr($e['time_iso']) . '">' . esc_html($e['time_short']) . '</td>'
                . '<td class="gvfw-logip">' . esc_html($e['ip']) . '</td>'
                . '<td class="gvfw-logreason"><span class="gvfw-badge ' . esc_attr($badgeClass) . '">' . esc_html($friendly) . '</span> <span class="gvfw-code">(' . esc_html($e['code']) . ')</span></td>'
                . '<td class="gvfw-loguri" title="' . esc_attr($e['uri']) . '">' . esc_html(self::truncate($e['uri'], 70)) . '</td>'
                . '<td class="gvfw-logua" title="' . esc_attr($e['ua']) . '">' . esc_html(self::truncate($e['ua'], 90)) . '</td>'
                . '</tr>';
        }
        if ($rows === '') return '<p class="description">No parsable entries.</p>';

        $dl = wp_nonce_url(admin_url('admin-post.php?action=gvfw_download_log'), 'gvfw_download_log');

        $html  = '<div class="gvfw-logtable-wrapper"><table class="gvfw-logtable"><tbody>' . $rows . '</tbody></table></div>';
        $html .= '<div class="gvfw-log-actions">';
        $html .= '<a class="button button-secondary" href="' . esc_url($dl) . '">Download</a>';
        $html .= '<a class="button button-secondary" href="' . esc_url(add_query_arg(['page'=>self::OPT], admin_url('options-general.php'))) . '">Refresh</a>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Parse one log line of format:
     * [ISO8601] IP "<reason> <code>" "URI" UA="UserAgent" [optional UN="user"]
     */
    private static function parse_log_line($ln) {
        $ln = trim($ln);
        if ($ln === '') return false;

        if (!preg_match(
            '/^\[(.*?)\]\s+(\S+)\s+([a-z0-9\-]+)\s+(\d{3})\s+"([^"]*)"(?:\s+UA="([^"]*)")?(?:\s+UN="([^"]*)")?/i',
            $ln, $m)) return false;

        $iso    = $m[1];
        $ip     = $m[2];
        $reason = strtolower($m[3]);
        $code   = (int)$m[4];
        $uri    = $m[5];
        $ua     = $m[6] ?? '';
        $user   = $m[7] ?? '';

        $time_short = $iso;
        try {
            if (function_exists('wp_timezone')) {
                $dt = new DateTime($iso);
                $dt->setTimezone(wp_timezone());
                $time_short = $dt->format('H:i');
            }
        } catch (\Throwable $e) {}

        return [
            'time_iso'   => $iso,
            'time_short' => $time_short,
            'ip'         => $ip,
            'reason'     => $reason,
            'code'       => $code,
            'uri'        => $uri,
            'ua'         => $ua,
            'user'       => $user,
        ];
    }

    /* Map internal reasons to human-friendly labels */
    private static function friendly_reason($r) {
        switch ($r) {
            case 'xmlrpc-block':  return 'XML-RPC blocked';
            case 'bad-ua':        return 'Bad user-agent';
            case 'sig-sql-xss':   return 'Injection signature';
            case 'rate-login':    return 'Login rate-limit';
            case 'rate-xmlrpc':   return 'XML-RPC rate-limit';
            case 'denylist':      return 'Denylist';
            case 'login-ok':      return 'Login success';
            case 'login-fail':    return 'Login failed';
            default:              return ucfirst(str_replace('-', ' ', $r));
        }
    }

    private static function truncate($s, $len = 80) {
        $s = (string)$s;
        return (strlen($s) <= $len) ? $s : (substr($s, 0, $len - 1) . '…');
    }

    private static function tail_file($file, $lines = 50, $max_bytes = 131072) {
        $size = @filesize($file);
        if ($size === false) return [];
        $read = min($size, max(1024, (int)$max_bytes));

        $fp = @fopen($file, 'rb');
        if (!$fp) return [];

        @fseek($fp, -$read, SEEK_END);
        $data = @fread($fp, $read);
        @fclose($fp);
        if ($data === false) return [];

        $arr = preg_split("/\r\n|\n|\r/", $data);
        if ($size > $read && count($arr)) array_shift($arr);
        $arr = array_values(array_filter($arr, 'strlen'));
        $last = array_slice($arr, -$lines);

        return $last;
    }

    public static function render_logs() {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
    if (!current_user_can($cap)) wp_die('Unauthorized', 'Error', ['response' => 403]);
        echo '<div class="wrap"><h1>GV Firewall Logs</h1>';

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
    if (!current_user_can($cap)) wp_die('Unauthorized', 'Error', ['response' => 403]);
    if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'gvfw_download_log')) wp_die('Bad nonce', 403);

    $file = self::latest_log_path();
    if (!$file || !is_readable($file)) wp_die('No log available', 404);

    while (ob_get_level()) { ob_end_clean(); }

    // Prevent intermediary/proxy caching
    nocache_headers();

    header('Content-Type: text/plain');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
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
                $is_ssl = is_ssl() || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
                if ($is_ssl) return;
                if (self::is_sensitive_route()) {
                    $host = $_SERVER['HTTP_HOST'] ?? '';
                    $req  = $_SERVER['REQUEST_URI'] ?? '/';
                    wp_safe_redirect('https://' . $host . $req, 301);
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

private static function client_ip() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    // Prefer CF-Connecting-IP if coming through a trusted proxy
    $trusted = apply_filters('gvfw_trusted_proxies', []);
    if (!empty($trusted) && self::ip_in_any($ip, $trusted)) {
        $cf = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
        if ($cf && filter_var($cf, FILTER_VALIDATE_IP)) return $cf;

        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff) {
            $cand = trim(explode(',', $xff)[0]);
            if (filter_var($cand, FILTER_VALIDATE_IP)) return $cand;
        }
    }
    return $ip;
}


    private static function ip_in_any($ip, $cidrs) {
        foreach ((array)$cidrs as $c) { if (self::cidr_match($ip, $c)) return true; }
        return false;
    }

 private static function ip_in_list($ip, $list_csv) {
    // split on comma OR any whitespace
    $items = preg_split('~[\s,]+~', (string)$list_csv, -1, PREG_SPLIT_NO_EMPTY);
    foreach ($items as $item) {
        if (strpos($item, '/') !== false && self::cidr_match($ip, $item)) return true;
        // exact-IP match across v4/v6 canonical forms
        if (@inet_pton($item) !== false && @inet_pton($ip) !== false) {
            if (strlen(inet_pton($item)) === strlen(inet_pton($ip)) && inet_pton($item) === inet_pton($ip)) return true;
        }
    }
    return false;
}

// Replace the old cidr_match() with this multi-family version
private static function cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) return false;

    list($subnet, $mask) = explode('/', $cidr, 2);
    $mask = (int)$mask;

    $ip_bin  = @inet_pton($ip);
    $net_bin = @inet_pton($subnet);
    if ($ip_bin === false || $net_bin === false) return false;

    $len = strlen($ip_bin); // 4 for IPv4, 16 for IPv6
    if ($len !== strlen($net_bin)) return false;

    $max = ($len === 4) ? 32 : 128;
    if ($mask < 0 || $mask > $max) return false;

    $full_bytes = intdiv($mask, 8);
    $rem_bits   = $mask % 8;

    // Compare full bytes
    if ($full_bytes > 0) {
        if (strncmp($ip_bin, $net_bin, $full_bytes) !== 0) return false;
    }

    // Compare remaining bits
    if ($rem_bits === 0) return true;

    $ip_byte  = ord($ip_bin[$full_bytes]);
    $net_byte = ord($net_bin[$full_bytes]);
    $mask_byte = (0xFF << (8 - $rem_bits)) & 0xFF;

    return (($ip_byte & $mask_byte) === ($net_byte & $mask_byte));
}


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
        // Try fast path
        $body = @file_get_contents('php://input', false, null, 0, 4096);
        // Fallback if host disables or errors
        if ($body === false || $body === null) {
            $h = @fopen('php://input', 'rb');
            if ($h) { $body = @stream_get_contents($h, 4096); @fclose($h); }
            if ($body === false || $body === null) $body = '';
        }
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

private static function block($code, $reason, $ip, $uri, $ua) {
    status_header($code);
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: frame-ancestors 'none'");
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-GVFW: ' . $reason);
    self::log("$reason $code", $ip, $uri, $ua);
    echo "Request blocked ($reason).\n";
    exit;
}

    private static function log($event, $ip, $uri, $ua, $extra = []) {
        $o = self::get();
        if (!$o['log_enabled']) return;

        $upload = wp_get_upload_dir();
        if (empty($upload['basedir'])) return;

        $dir = trailingslashit($upload['basedir']) . 'gv-firewall';
        self::ensure_logs_dir_secure($dir);

        $ua  = substr(str_replace(["\n","\r"], ' ', (string)$ua), 0, 512);
        $uri = substr(str_replace(["\n","\r"], ' ', (string)$uri), 0, 512);

        $kv = '';
        foreach ((array)$extra as $k => $v) {
            $k = preg_replace('~[^A-Z0-9_-]~i','',$k);
            $v = substr(str_replace(["\n","\r"], ' ', (string)$v), 0, 256);
            $kv .= ' ' . $k . '="' . $v . '"';
        }

        $file = $dir . '/gvf-' . gmdate('Y-m-d') . '.log';
        $line = sprintf("[%s] %s %s \"%s\" UA=\"%s\"%s\n", gmdate('c'), $ip, $event, $uri, $ua, $kv);

        if ($fh = @fopen($file, 'a')) { @fwrite($fh, $line); @fclose($fh); @chmod($file,0640); }
        else { @file_put_contents($file, $line, FILE_APPEND|LOCK_EX); @chmod($file,0640); }

        self::prune_logs($dir, (int)$o['log_days']);
    }

    private static function ensure_logs_dir_secure($dir) {
        if (!is_dir($dir)) @wp_mkdir_p($dir);
        if (!file_exists("$dir/index.html")) @file_put_contents("$dir/index.html", "");
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

public static function add_action_links($links) {
    $custom = [
        '<a href="https://gardevault.eu/security-audit" target="_blank" style="color:#3db634;font-weight:bold;">Get Infosec Audit</a>'
    ];
    if (!class_exists('GV_Core')) {
        $custom[] = '<a href="https://gardevault.eu/plugins/gv-core/" target="_blank">Download GV Core</a>';
        $custom[] = '<a href="https://github.com/Davekrush/GV-Core-plugin" target="_blank">GitHub</a>';
    }
    return array_merge($custom, $links);

    add_action('admin_notices', function () {
    if (!current_user_can('manage_options') || class_exists('GV_Core')) return;
    $screen = get_current_screen();
    if (!$screen) return;
    if (strpos($screen->id, 'gvfw') === false && strpos($screen->id, 'gardevault') === false) return;

    echo '<div class="notice notice-info is-dismissible"><p><strong>GardeVault Core</strong> enhances cross-plugin settings and telemetry.</p><p><a class="button button-primary" href="https://gardevault.eu/plugins/gv-core/" target="_blank" rel="noopener">Download GV Core</a> <a class="button" href="https://github.com/Davekrush/GV-Core-plugin" target="_blank" rel="noopener">GitHub</a></p></div>';
});

}



    /* ---------- Recent logins widget (no inline CSS) ---------- */
    private static function recent_login_block($n = 50) {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) return '<p class="description">No permission to view logs.</p>';
        $latest = self::latest_log_path();
        if (!$latest) return '<p class="description">No log file yet.</p>';
        $lines = self::tail_file($latest, max(1,(int)$n), 256*1024);
        if (!$lines) return '<p class="description">No recent entries.</p>';

        $rows = '';
        foreach ($lines as $ln) {
            $e = self::parse_log_line($ln);
            if (!$e) continue;
            if ($e['reason'] !== 'login-ok' && $e['reason'] !== 'login-fail') continue;
            $cls = ($e['reason']==='login-ok') ? 'gvfw-ok' : 'gvfw-fail';
            $who = $e['user'] !== '' ? $e['user'] : 'unknown';
            $rows .= '<tr class="gvfw-loginrow">'
                  . '<td class="gvfw-login-time" title="'.esc_attr($e['time_iso']).'">'.esc_html($e['time_short']).'</td>'
                  . '<td class="gvfw-login-user">'.esc_html($who).'</td>'
                  . '<td class="gvfw-login-ip">'.esc_html($e['ip']).'</td>'
                  . '<td class="gvfw-login-reason"><span class="gvfw-badge2 '.$cls.'">'.esc_html(self::friendly_reason($e['reason'])).'</span> ('.esc_html($e['code']).')</td>'
                  . '<td class="gvfw-loginua" title="'.esc_attr($e['ua']).'">'.esc_html(self::truncate($e['ua'],90)).'</td>'
                  . '</tr>';
        }
        if ($rows==='') return '<p class="description">No login entries.</p>';

        $html  = '<div class="gvfw-logins-wrapper"><table class="gvfw-logins"><tbody>'.$rows.'</tbody></table></div>';
        return $html;
    }

    
}

GVFW::init();
