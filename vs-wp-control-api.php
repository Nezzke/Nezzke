<?php
/**
 * Plugin Name: VS WP Control API
 * Description: Controlled REST API for managing WordPress content, media, menus and WooCommerce with scoped Bearer authentication, audit logging and rollback.
 * Version: 0.3.1
 * Author: Ворота Столицы
 * Requires at least: 6.5
 * Requires PHP: 8.1
 * Text Domain: vs-wp-control
 */

if (!defined('ABSPATH')) {
    exit;
}

define('VS_WP_CONTROL_VERSION', '0.3.1');
define('VS_WP_CONTROL_FILE', __FILE__);
define('VS_WP_CONTROL_DIR', plugin_dir_path(__FILE__));

require_once VS_WP_CONTROL_DIR . 'includes/class-vs-wp-control-auth.php';
require_once VS_WP_CONTROL_DIR . 'includes/class-vs-wp-control-audit.php';
require_once VS_WP_CONTROL_DIR . 'includes/class-vs-wp-control-plugins.php';
require_once VS_WP_CONTROL_DIR . 'includes/class-vs-wp-control-rest.php';
require_once VS_WP_CONTROL_DIR . 'includes/class-vs-wp-control-admin.php';

register_activation_hook(__FILE__, static function (): void {
    VS_WP_Control_Audit::install();
    update_option('vs_wp_control_db_version', VS_WP_CONTROL_VERSION, false);
    if (false === get_option('vs_wp_control_scopes', false)) {
        add_option('vs_wp_control_scopes', ['read', 'content', 'publish', 'media', 'commerce', 'system'], '', false);
    }
});

add_action('plugins_loaded', static function (): void {
    VS_WP_Control_Audit::init();
    VS_WP_Control_REST::init();
    if (is_admin()) {
        VS_WP_Control_Admin::init();
    }
});
