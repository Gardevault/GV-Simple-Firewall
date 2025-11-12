<?php
/*
Plugin Name: GV Simple Firewall
Description: Minimal WordPress request firewall. XML-RPC blocking, bad-UA filters, basic injection signatures, login/XML-RPC rate limits, optional HTTPS enforcement, optional security headers, REST/user-enum hardening, HTTP method gate, lightweight file logging. Settings: Settings → GV Firewall.
Version: 2.0
Author: GardeVault
Update URI: false
Author URI: https://gardevault.eu
Plugin URI: https://gardevault.eu/plugins/gv-simple-firewall
*/

if (!defined('ABSPATH')) exit;

class GVFW {
    const OPT = 'gvfw_settings';
    const VER = '2.0';

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
            // Core gates
            'require_ssl'       => 0,
            'block_xmlrpc'      => 1,
            'remove_x_pingback' => 1,
            'bad_ua'            => 1,
            'sig_sql_xss'       => 1,
            'method_gate'       => 1,

            // Rate limits
            'rl_login_n'        => 30,
            'rl_login_win'      => 600,
            'rl_xmlrpc_n'       => 30,
            'rl_xmlrpc_win'     => 600,
            'per_user_rl'       => 1,
            'per_user_rl_n'     => 10,
            'per_user_rl_win'   => 600,

            // REST and user enumeration
            'rest_lock'         => 1,
            'user_enum_block'   => 1,

            // Headers
            'hdrs_enable'       => 1,
            'csp_report_only'   => 1,

            // IP lists
            'allowlist'         => '',
            'denylist'          => '',

            // Logging
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

        // Top-level "GV Firewall"
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

            // Logs in Tools
            $cap_logs = apply_filters('gvfw_view_logs_cap', 'manage_options');
            add_management_page('GV Firewall Logs', 'GV Firewall Logs', $cap_logs, 'gvfw_logs', [__CLASS__, 'render_logs']);
        }, 9);

        add_action('admin_init', [__CLASS__, 'register']);

        // Plugin action links
        $plugin_file = plugin_basename(__FILE__);
        add_filter('plugin_action_links_' . $plugin_file, [__CLASS__, 'add_action_links']);

        // Optional notice about GV Core
        add_action('admin_notices', function () {
            if (!current_user_can('manage_options') || class_exists('GV_Core')) return;
            $screen = get_current_screen();
            if (!$screen) return;
            if (strpos($screen->id, 'gvfw') === false && strpos($screen->id, 'gardevault') === false) return;
            echo '<div class="notice notice-info is-dismissible"><p><strong>GardeVault Core</strong> enhances cross-plugin settings and telemetry.</p><p><a class="button button-primary" href="https://gardevault.eu/plugins/gv-core/" target="_blank" rel="noopener">Download GV Core</a> <a class="button" href="https://github.com/Davekrush/GV-Core-plugin" target="_blank" rel="noopener">GitHub</a></p></div>';
        });
    }

    public static function register() {
        register_setting(self::OPT, self::OPT, [__CLASS__, 'sanitize']);
    }

    public static function sanitize($in) {
        $d = self::defaults(); $out = [];

        // Core gates
        $out['require_ssl']       = !empty($in['require_ssl']) ? 1 : 0;
        $out['block_xmlrpc']      = !empty($in['block_xmlrpc']) ? 1 : 0;
        $out['remove_x_pingback'] = !empty($in['remove_x_pingback']) ? 1 : 0;
        $out['bad_ua']            = !empty($in['bad_ua']) ? 1 : 0;
        $out['sig_sql_xss']       = !empty($in['sig_sql_xss']) ? 1 : 0;
        $out['method_gate']       = !empty($in['method_gate']) ? 1 : 0;

        // Rate limits
        $out['rl_login_n']        = max(1, intval($in['rl_login_n'] ?? $d['rl_login_n']));
        $out['rl_login_win']      = max(30, intval($in['rl_login_win'] ?? $d['rl_login_win']));
        $out['rl_xmlrpc_n']       = max(1, intval($in['rl_xmlrpc_n'] ?? $d['rl_xmlrpc_n']));
        $out['rl_xmlrpc_win']     = max(30, intval($in['rl_xmlrpc_win'] ?? $d['rl_xmlrpc_win']));
        $out['per_user_rl']       = !empty($in['per_user_rl']) ? 1 : 0;
        $out['per_user_rl_n']     = max(1, intval($in['per_user_rl_n'] ?? $d['per_user_rl_n']));
        $out['per_user_rl_win']   = max(30, intval($in['per_user_rl_win'] ?? $d['per_user_rl_win']));

        // REST and user enumeration
        $out['rest_lock']         = !empty($in['rest_lock']) ? 1 : 0;
        $out['user_enum_block']   = !empty($in['user_enum_block']) ? 1 : 0;

        // Headers
        $out['hdrs_enable']       = !empty($in['hdrs_enable']) ? 1 : 0;
        $out['csp_report_only']   = !empty($in['csp_report_only']) ? 1 : 0;

        // IP lists
        $out['allowlist']         = substr(sanitize_text_field($in['allowlist'] ?? ''), 0, 1000);
        $out['denylist']          = substr(sanitize_text_field($in['denylist']  ?? ''), 0, 1000);

        // Logging
        $out['log_enabled']       = !empty($in['log_enabled']) ? 1 : 0;
        $out['log_days']          = max(1, intval($in['log_days'] ?? $d['log_days']));
        $out['log_logins']        = !empty($in['log_logins']) ? 1 : 0;

        return $out;
    }

    public static function render() {
        if (!current_user_can('manage_options')) return;
        $o = self::get();

        // quick stats
        $protections_on = (int)$o['require_ssl'] + (int)$o['block_xmlrpc'] + (int)$o['remove_x_pingback'] + (int)$o['bad_ua'] + (int)$o['sig_sql_xss'] + (int)$o['method_gate'] + (int)$o['rest_lock'] + (int)$o['user_enum_block'] + (int)$o['hdrs_enable'];
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
        self::checkbox_row('HTTP method gate (allow GET/HEAD/POST)', 'method_gate', $o['method_gate']);
        echo '</div></section>';

        // Rate limits
        echo '<section class="gvfw-card"><h2>Rate limits</h2><div class="gvfw-fields gvfw-4col">';
        self::number_row('Login attempts', 'rl_login_n', $o['rl_login_n'], 1, 1000);
        self::number_row('Login window (s)', 'rl_login_win', $o['rl_login_win'], 30, 7200);
        self::number_row('XML-RPC attempts', 'rl_xmlrpc_n', $o['rl_xmlrpc_n'], 1, 1000);
        self::number_row('XML-RPC window (s)', 'rl_xmlrpc_win', $o['rl_xmlrpc_win'], 30, 7200);
        echo '</div>';
        echo '<div class="gvfw-fields gvfw-4col">';
        self::checkbox_row('Per-username login throttle', 'per_user_rl', $o['per_user_rl']);
        self::number_row('Per-user attempts', 'per_user_rl_n', $o['per_user_rl_n'], 1, 100);
        self::number_row('Per-user window (s)', 'per_user_rl_win', $o['per_user_rl_win'], 30, 7200);
        echo '</div></section>';

        // REST & enumeration
        echo '<section class="gvfw-card"><h2>REST & Enumeration</h2><div class="gvfw-fields gvfw-2col">';
        self::checkbox_row('Lock down /wp-json/wp/v2/users* for anonymous', 'rest_lock', $o['rest_lock']);
        self::checkbox_row('Block ?author=N user enumeration', 'user_enum_block', $o['user_enum_block']);
        echo '</div></section>';

        // Security headers
        echo '<section class="gvfw-card"><h2>Security headers</h2><div class="gvfw-fields gvfw-2col">';
        self::checkbox_row('Send security headers (HSTS, XFO, X-CTO, Referrer-Policy, Permissions-Policy, CSP)', 'hdrs_enable', $o['hdrs_enable']);
        self::checkbox_row('CSP in Report-Only (recommended for testing)', 'csp_report_only', $o['csp_report_only']);
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
        echo self::recent_log_block_hardened(50);
        echo '</div>';

        // Recent logins panel
        echo '<div class="gvfw-card">';
        echo '<h2>Recent logins</h2>';
        echo self::recent_login_block_hardened(50);
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

    /**
     * Gets the 50 most recent block entries from *all* log files.
     */
    private static function recent_log_block_hardened($n = 50) {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) return '<p class="description">No permission to view logs.</p>';

        $all_log_files = self::get_all_log_paths(); // Use our new helper
        if (empty($all_log_files)) {
            return '<p class="description">No log file yet.</p>';
        }

        $lines = [];
        $lines_needed = max(1, (int)$n);
        $bytes_to_read = 256 * 1024; // Read a 256KB chunk at a time

        // Loop through all log files, starting with the newest
        foreach ($all_log_files as $file) {
            if (count($lines) >= $lines_needed) break; // We have enough

            $new_lines = self::tail_file($file, $lines_needed * 5, $bytes_to_read); // Get a batch of lines
            if (empty($new_lines)) continue;

            // Go through lines *in reverse* (newest first)
            foreach (array_reverse($new_lines) as $ln) {
                $e = self::parse_log_line($ln);
                if (!$e) continue;
                if (strpos($e['reason'], 'login-') === 0) continue; // Exclude logins

                // Add to our master list
                $lines[] = $e;
                if (count($lines) >= $lines_needed) break 2; // We have enough, break both loops
            }
        }

        if (empty($lines)) {
            return '<p class="description">No recent entries.</p>';
        }

        $rows = '';
        foreach ($lines as $e) {
            $badgeClass = ($e['code'] == 429) ? 'warn' : 'block';
            $friendly = self::friendly_reason($e['reason']);

            $rows .= '<tr class="gvfw-logrow">'
                . '<td class="gvfw-logtime" title="' . esc_attr($e['time_iso']) . '">' . esc_html($e['time_short']) . '</td>'
                . '<td class="gvfw-logip">' . esc_html($e['ip']) . '</td>'
                . '<td class="gvfw-logreason"><span class="gvfw-badge ' . esc_attr($badgeClass) . '">' . esc_html($friendly) . '</span> <span class="gvfw-code">(' . esc_html($e['code']) . ')</span></td>'
                . '<td class="gvfw-loguri" title="' . esc_attr($e['uri']) . '">' . esc_html(self::truncate($e['uri'], 70)) . '</td>'
                . '<td class="gvfw-logua" title="' . esc_attr($e['ua']) . '">' . esc_html(self::truncate($e['ua'], 90)) . '</td>'
                . '</tr>';
        }

        if ($rows === '') {
            return '<p class="description">No parsable entries.</p>';
        }

        // Get download URL for the *latest* log as a quick link
        $dl = wp_nonce_url(admin_url('admin-post.php?action=gvfw_download_log'), 'gvfw_download_log');

        $html = '<div class="gvfw-logtable-wrapper"><table class="gvfw-logtable"><tbody>' . $rows . '</tbody></table></div>';
        $html .= '<div class="gvfw-log-actions">';
        $html .= '<a class="button button-secondary" href="' . esc_url($dl) . '">Download Latest</a>';
        // Link to the new advanced log page
        $html .= '<a class="button button-secondary" href="' . esc_url(admin_url('tools.php?page=gvfw_logs')) . '">View All Logs</a>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Gets the 50 most recent login entries from *all* log files.
     */
    private static function recent_login_block_hardened($n = 50) {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) return '<p class="description">No permission to view logs.</p>';

        $all_log_files = self::get_all_log_paths(); // Use our new helper
        if (empty($all_log_files)) {
            return '<p class="description">No log file yet.</p>';
        }

        $lines = [];
        $lines_needed = max(1, (int)$n);
        $bytes_to_read = 256 * 1024;

        // Loop through all log files, starting with the newest
        foreach ($all_log_files as $file) {
            if (count($lines) >= $lines_needed) break;

            $new_lines = self::tail_file($file, $lines_needed * 5, $bytes_to_read);
            if (empty($new_lines)) continue;

            foreach (array_reverse($new_lines) as $ln) {
                $e = self::parse_log_line($ln);
                if (!$e) continue;
                // THIS IS THE ONLY CHANGE: only include logins
                if ($e['reason'] !== 'login-ok' && $e['reason'] !== 'login-fail') continue;

                $lines[] = $e;
                if (count($lines) >= $lines_needed) break 2;
            }
        }

        if (empty($lines)) {
            return '<p class="description">No login entries.</p>';
        }

        $rows = '';
        foreach ($lines as $e) {
            $cls = ($e['reason'] === 'login-ok') ? 'gvfw-ok' : 'gvfw-fail';
            $who = $e['user'] !== '' ? $e['user'] : 'unknown';
            $rows .= '<tr class="gvfw-loginrow">'
                . '<td class="gvfw-login-time" title="' . esc_attr($e['time_iso']) . '">' . esc_html($e['time_short']) . '</td>'
                . '<td class="gvfw-login-user">' . esc_html($who) . '</td>'
                . '<td class="gvfw-login-ip">' . esc_html($e['ip']) . '</td>'
                . '<td class="gvfw-login-reason"><span class="gvfw-badge2 ' . $cls . '">' . esc_html(self::friendly_reason($e['reason'])) . '</span> (' . esc_html($e['code']) . ')</td>'
                . '<td class="gvfw-loginua" title="' . esc_attr($e['ua']) . '">' . esc_html(self::truncate($e['ua'], 90)) . '</td>'
                . '</tr>';
        }

        $html = '<div class="gvfw-logins-wrapper"><table class="gvfw-logins"><tbody>' . $rows . '</tbody></table></div>';
        return $html;
    }

    /**
     * Parse one log line of format:
     * [ISO8601] IP "<reason> <code>" "URI" UA="UserAgent" [optional UN="user"]
     */
private static function parse_log_line($ln) {
    $ln = trim($ln);
    if ($ln === '') return false;

    // Parse the fixed head: [ISO] IP reason code "URI"
    if (!preg_match('/^\[(.*?)\]\s+(\S+)\s+([a-z0-9\-]+)\s+(\d{3})\s+"([^"]*)"/i', $ln, $m)) {
        return false;
    }
    $iso    = $m[1];
    $ip     = $m[2];
    $reason = strtolower($m[3]);
    $code   = (int)$m[4];
    $uri    = $m[5];

    // Parse all key="value" pairs that follow (order-agnostic)
    $pairs = [];
    if (preg_match_all('/\s([A-Z_]+)="([^"]*)"/', $ln, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $kv) $pairs[$kv[1]] = $kv[2];
    }

    $ua   = $pairs['UA']   ?? '';
    $user = $pairs['UN']   ?? '';
    // Optional extras if you want to display them later
    $rule   = $pairs['RULE']   ?? '';
    $source = $pairs['SOURCE'] ?? '';
    $key    = $pairs['KEY']    ?? '';
    $val    = $pairs['VALUE']  ?? '';

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
        // keep extras if needed by UI later
        'rule'       => $rule,
        'source'     => $source,
        'kv_key'     => $key,
        'kv_val'     => $val,
    ];
}


    /* Map internal reasons to human-friendly labels */
    private static function friendly_reason($r) {
        switch ($r) {
            case 'sig-hardened': return 'Injection signature';
            case 'sig-body':     return 'Body signature';
            case 'xmlrpc-block':  return 'XML-RPC blocked';
            case 'bad-ua':        return 'Bad user-agent';
            case 'sig-sql-xss':   return 'Injection signature';
            case 'rate-login':    return 'Login rate-limit';
            case 'rate-xmlrpc':   return 'XML-RPC rate-limit';
            case 'denylist':      return 'Denylist';
            case 'bad-method':    return 'HTTP method blocked';
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

        echo '<div class="wrap gvfw-wrap">'; // Added class for styling
        echo '<h1>GV Firewall Logs</h1>';

        $all_files = self::get_all_log_paths();
        
        if (empty($all_files)) {
            echo '<p class="description">No log files found.</p>';
            echo '</div>';
            return;
        }

        echo '<div class="gvfw-card" style="max-width: 800px;">'; // Use a card for nice styling
        echo '<table class="wp-list-table widefat striped gvfw-log-list">';
        echo '<thead><tr><th scope="col">Log File</th><th scope="col">File Size</th><th scope="col">Actions</th></tr></thead>';
        echo '<tbody>';

        foreach ($all_files as $file_path) {
            $file_name = basename($file_path);
            $file_size = @filesize($file_path);
            $file_size_kb = $file_size ? round($file_size / 1024, 2) : 0;

            // Create a secure, nonced URL for this specific file
            $download_url = wp_nonce_url(
                admin_url('admin-post.php?action=gvfw_download_log&log_file=' . esc_attr($file_name)),
                'gvfw_download_log'
            );

            echo '<tr>';
            echo '<td data-col="Log File"><strong>' . esc_html($file_name) . '</strong></td>';
            echo '<td data-col="File Size">' . esc_html($file_size_kb) . ' KB</td>';
            echo '<td data-col="Actions"><a href="' . esc_url($download_url) . '" class="button button-primary">Download</a></td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
        echo '</div>';
    }

    public static function handle_download_log() {
        $cap = apply_filters('gvfw_view_logs_cap', 'manage_options');
        if (!current_user_can($cap)) wp_die('Unauthorized', 'Error', ['response' => 403]);
        if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'gvfw_download_log')) wp_die('Bad nonce', 403);

        $log_dir = self::logs_dir();
        $file = '';

        // Check if a specific file is requested
        if (!empty($_GET['log_file'])) {
            $req_file = basename($_GET['log_file']); // Use basename() to prevent path traversal

            // Security: Sanity check the file name
            if (empty($req_file) || strpos($req_file, 'gvf-') !== 0 || pathinfo($req_file, PATHINFO_EXTENSION) !== 'log') {
                wp_die('Invalid log file specified.', 400);
            }

            $file = $log_dir . '/' . $req_file;

            // Security: Ensure the file is *actually* in the log directory
            $safe_dir = realpath($log_dir);
            $safe_file = realpath($file);
            
            if (!$safe_file || !$safe_dir || strpos($safe_file, $safe_dir) !== 0) {
                wp_die('Security check failed.', 403);
            }

        } else {
            // Fallback to old logic: download the latest file
            $file = self::latest_log_path();
        }

        if (!$file || !is_readable($file)) wp_die('No log available or file not found.', 404);

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

        // Main gate and headers
        add_action('init', [__CLASS__, 'gate'], 0);
        if ($o['hdrs_enable']) {
            add_action('send_headers', [__CLASS__, 'send_security_headers'], 0);
        }

        // REST lockdown and user enumeration
        if ($o['rest_lock']) {
            add_filter('rest_authentication_errors', [__CLASS__, 'rest_lockdown'], 10);
        }
        if ($o['user_enum_block']) {
            add_action('init', [__CLASS__, 'block_user_enum'], 1);
        }

        // HTTP method allowlist
        if ($o['method_gate']) {
            add_action('init', [__CLASS__, 'method_gate'], 0);
        }
    }

    public static function send_security_headers() {
        if (headers_sent()) return;

        // HSTS only when HTTPS
        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=15552000; includeSubDomains; preload');
        }

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');

        // CSP: safe baseline for WP; customize sources as needed
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://www.googletagmanager.com https://www.google-analytics.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: blob: https://secure.gravatar.com https://www.google-analytics.com",
            "font-src 'self' data: https://fonts.gstatic.com",
            "connect-src 'self' https://www.google-analytics.com https://www.googletagmanager.com",
            "frame-src https://www.youtube.com https://player.vimeo.com https://www.google.com",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'"
        ]);

        $o = self::get();
        if (!empty($o['csp_report_only'])) {
            header('Content-Security-Policy-Report-Only: ' . $csp);
        } else {
            header('Content-Security-Policy: ' . $csp);
        }
    }

    public static function rest_lockdown($result) {
        if (!is_user_logged_in()) {
            $req = $_SERVER['REQUEST_URI'] ?? '';
            if (strpos($req, '/wp-json/wp/v2/users') !== false) {
                return new WP_Error('forbidden', 'Forbidden', ['status' => 403]);
            }
        }
        return $result;
    }

    public static function block_user_enum() {
        if (is_admin()) return;
        $req = $_SERVER['REQUEST_URI'] ?? '';
        if (preg_match('~[\?&]author=\d+~', $req)) {
            status_header(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo "Not found\n";
            exit;
        }
    }

    public static function method_gate() {
        $m = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if (!in_array($m, ['GET','HEAD','POST'], true)) {
            self::block_hardened(405, 'bad-method', self::client_ip(), ($_SERVER['REQUEST_URI'] ?? ''), ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        }
        if ($m === 'TRACE' || $m === 'TRACK') {
            self::block_hardened(405, 'bad-method', self::client_ip(), ($_SERVER['REQUEST_URI'] ?? ''), ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        }
    }

    public static function gate() {
        if (defined('WP_CLI') && WP_CLI) return;
        if (defined('DOING_CRON') && DOING_CRON) return;

        $o   = self::get();
        $ip  = self::client_ip();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($o['allowlist'] && self::ip_in_list($ip, $o['allowlist'])) return;
        if ($o['denylist'] && self::ip_in_list($ip, $o['denylist'])) self::block_hardened(403, 'denylist', $ip, $uri, $ua);

        if ($o['block_xmlrpc'] && self::is_xmlrpc()) self::block_hardened(403, 'xmlrpc-block', $ip, $uri, $ua);
        if ($o['bad_ua'] && self::is_bad_ua($ua)) self::block_hardened(403, 'bad-ua', $ip, $uri, $ua);
        
        // This is the special one from my instructions
        if ($o['sig_sql_xss']) {
            self::trips_signatures_hardened();
        }

        // Rate limits: IP scoped
        if (self::is_login())  self::rate_limit('login',  $o['rl_login_n'],  $o['rl_login_win']);
        if (self::is_xmlrpc()) self::rate_limit('xmlrpc', $o['rl_xmlrpc_n'], $o['rl_xmlrpc_win']);

        // Optional per-username throttle
        if ($o['per_user_rl'] && self::is_login() && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $u = strtolower(trim($_POST['log'] ?? ''));
            if ($u !== '') {
                self::rate_limit('login_user:' . $u, $o['per_user_rl_n'], $o['per_user_rl_win']);
            }
        }
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
        $items = preg_split('~[\s,]+~', (string)$list_csv, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($items as $item) {
            if (strpos($item, '/') !== false && self::cidr_match($ip, $item)) return true;
            if (@inet_pton($item) !== false && @inet_pton($ip) !== false) {
                if (strlen(inet_pton($item)) === strlen(inet_pton($ip)) && inet_pton($item) === inet_pton($ip)) return true;
            }
        }
        return false;
    }

    // IPv4/IPv6 CIDR match
    private static function cidr_match($ip, $cidr) {
        if (strpos($cidr, '/') === false) return false;

        list($subnet, $mask) = explode('/', $cidr, 2);
        $mask = (int)$mask;

        $ip_bin  = @inet_pton($ip);
        $net_bin = @inet_pton($subnet);
        if ($ip_bin === false || $net_bin === false) return false;

        $len = strlen($ip_bin); // 4 or 16
        if ($len !== strlen($net_bin)) return false;

        $max = ($len === 4) ? 32 : 128;
        if ($mask < 0 || $mask > $max) return false;

        $full_bytes = intdiv($mask, 8);
        $rem_bits   = $mask % 8;

        if ($full_bytes > 0 && strncmp($ip_bin, $net_bin, $full_bytes) !== 0) return false;
        if ($rem_bits === 0) return true;

        $ip_byte   = ord($ip_bin[$full_bytes]);
        $net_byte  = ord($net_bin[$full_bytes]);
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

    private static function trips_signatures_hardened() {
        // 1. A much larger and more specific set of rules.
        // Sourced from various open-source projects (e.g., 7G Firewall)
        $signatures = [
            // SQL Injection
            '/(union|select|insert|cast|declare|drop|truncate|md5|benchmark)\s*\(.*\)/i',
            '/(\b(union|select)\b.{1,100}\b(from|into|benchmark)\b)/i',
            '/(\b(or|and)\b.{1,100}[\'"]?(\d+)[\'"]?\s*=\s*[\'"]?(\d+))/i', // '1'='1'
            '/(waitfor\s+delay\s*[\'"]\d+:\d+:\d+[\'"])/i', // SQL time-based
            '/(extractvalue|updatexml)\s*\(/i',

            // Cross-Site Scripting (XSS)
            '/(<script|%3Cscript)/i',
            '/(onerror|onload|onmouseover|onfocus|oninput)\s*=/i',
            '/(javascript|data|vbscript):/i',
            '/(src\s*=\s*["\']?javascript:)/i',

            // File Inclusion & Path Traversal
            '/(\.\.\/|\.\.\\)/', // ../
            '/(file_get_contents|include|require)\s*\(.*\)/i',
            '/(php:\/\/|expect:\/\/|glob:\/\/)/i',
            '/(LFI|RFI|local file inclusion|remote file inclusion)/i',

            // Command Injection
            '/(passthru|shell_exec|exec|system|proc_open|popen)\s*\(.*\)/i',
           '/(`|%60).+(`|%60)/i', // backticks
        ];

        // 2. Define what to scan
        $scan_targets = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => $_COOKIE,
            'SERVER' => [ // Only check specific, high-risk server keys
                'REQUEST_URI'     => $_SERVER['REQUEST_URI'] ?? '',
                'QUERY_STRING'    => $_SERVER['QUERY_STRING'] ?? '',
                'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]
        ];

        // 3. Recursive scanner function
        $scan_recursive = function ($array, $source_name) use (&$scan_recursive, $signatures) {
            foreach ($array as $key => $value) {
                if (is_string($key)) {
                    $decoded_key = urldecode($key);
                    foreach ($signatures as $rule) {
                        if (preg_match($rule, $decoded_key)) {
                            // Found a match in the KEY
                            return [
                                'rule'   => $rule,
                                'source' => $source_name,
                                'key'    => $key,
                                'value'  => '(key match)'
                            ];
                        }
                    }
                }

                if (is_string($value)) {
                    $decoded_value = urldecode($value);
                    foreach ($signatures as $rule) {
                        if (preg_match($rule, $decoded_value)) {
                            // Found a match in the VALUE
                            return [
                                'rule'   => $rule,
                                'source' => $source_name,
                                'key'    => $key,
                                'value'  => $value
                            ];
                        }
                    }
                } elseif (is_array($value)) {
                    // Recurse into sub-arrays
                    $result = $scan_recursive($value, $source_name . '[' . $key . ']');
                    if ($result) return $result; // Pass the finding up
                }
            }
            return false; // No match
        };

        // 4. Run the scan
        foreach ($scan_targets as $source_name => $data_array) {
            if (empty($data_array)) continue;
            
            $finding = $scan_recursive($data_array, $source_name);

            if ($finding) {
                // Pass the finding to the block function for logging
                self::block_hardened(
                    403, 
                    'sig-hardened', 
                    self::client_ip(), 
                    ($_SERVER['REQUEST_URI'] ?? ''), 
                    ($_SERVER['HTTP_USER_AGENT'] ?? ''),
                    $finding // Pass extra data
                );
            }
        }
        
        // Also scan the raw body (for JSON, XML, etc.)
        $body = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $body = @file_get_contents('php://input', false, null, 0, 16384); // 16KB scan
            if ($body === false || $body === null) $body = '';
        }

        if ($body !== '') {
            $decoded_body = strtolower(urldecode($body));
            foreach ($signatures as $rule) {
                if (preg_match($rule, $decoded_body)) {
                    self::block_hardened(
                        403, 
                        'sig-body', 
                        self::client_ip(), 
                        ($_SERVER['REQUEST_URI'] ?? ''), 
                        ($_SERVER['HTTP_USER_AGENT'] ?? ''),
                        ['rule' => $rule, 'source' => 'RAW_BODY', 'value' => substr($body, 0, 100) . '...']
                    );
                }
            }
        }

        return false; // No signatures tripped
    }

    private static function rate_limit($scope, $limit, $window) {
        $ip   = self::client_ip();
        $key  = 'gvfw_' . md5($scope . '|' . $ip);
        $now  = time();
        $buck = get_transient($key);
        if (!is_array($buck)) $buck = ['n' => 0, 'reset' => $now + $window];

        if ($now > $buck['reset']) $buck = ['n' => 0, 'reset' => $now + $window];
        $buck['n']++;
        set_transient($key, $buck, max(1, $buck['reset'] - $now));

        if ($buck['n'] > $limit) {
            self::block_hardened(429, "rate-$scope", $ip, ($_SERVER['REQUEST_URI'] ?? ''), ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        }
    }

    private static function block_hardened($code, $reason, $ip, $uri, $ua, $finding = []) {
        status_header($code);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: frame-ancestors 'none'");
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-GVFW: ' . $reason);

        // Prepare extra data for logging
        $extra = [];
        if (!empty($finding)) {
            $extra['RULE']   = $finding['rule'] ?? 'unknown';
            $extra['SOURCE'] = $finding['source'] ?? 'unknown';
            $extra['KEY']    = $finding['key'] ?? 'N/A';
            // Truncate the logged value
            $extra['VALUE']  = substr((string)($finding['value'] ?? ''), 0, 100); 
        }

        self::log("$reason $code", $ip, $uri, $ua, $extra);
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

    private static function get_all_log_paths() {
        $dir = self::logs_dir();
        if (!is_dir($dir)) return [];
        $files = glob($dir . '/gvf-*.log');
        if (!$files) return [];
        rsort($files, SORT_NATURAL);
        return $files;
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
    }
}

GVFW::init();