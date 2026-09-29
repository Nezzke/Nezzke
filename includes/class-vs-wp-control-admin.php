<?php
if (!defined('ABSPATH')) {
    exit;
}

final class VS_WP_Control_Admin {
    private const TOKEN_TRANSIENT_PREFIX = 'vs_wp_control_token_once_';

    public static function init(): void {
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_post_vs_wp_control_generate_token', [self::class, 'generate_token']);
        add_action('admin_post_vs_wp_control_revoke_token', [self::class, 'revoke_token']);
        add_action('admin_post_vs_wp_control_save_scopes', [self::class, 'save_scopes']);
    }

    public static function menu(): void {
        add_management_page('VS WP Control API', 'VS WP Control API', 'manage_options', 'vs-wp-control-api', [self::class, 'render']);
    }

    public static function render(): void {
        if (!current_user_can('manage_options')) {
            return;
        }
        $token = get_transient(self::TOKEN_TRANSIENT_PREFIX . get_current_user_id());
        if ($token) {
            delete_transient(self::TOKEN_TRANSIENT_PREFIX . get_current_user_id());
        }
        $scopes = VS_WP_Control_Auth::get_scopes();
        $base = rest_url('vs-wp-control/v1');
        ?>
        <div class="wrap">
            <h1>VS WP Control API</h1>
            <p>Управляемый REST API без произвольного выполнения PHP, shell-команд и прямых SQL-запросов.</p>
            <table class="widefat striped" style="max-width:1000px;margin:18px 0">
                <tbody>
                <tr><th style="width:220px">API base</th><td><code><?php echo esc_html($base); ?></code></td></tr>
                <tr><th>Токен</th><td><?php echo VS_WP_Control_Auth::has_token() ? '<strong>создан</strong>' : '<strong>не создан</strong>'; ?></td></tr>
                <tr><th>Health</th><td><code><?php echo esc_html($base . '/health'); ?></code></td></tr>
                </tbody>
            </table>
            <?php if ($token): ?>
                <div class="notice notice-warning"><p><strong>Скопируйте токен сейчас. Повторно он не показывается.</strong></p><p><code style="word-break:break-all"><?php echo esc_html($token); ?></code></p></div>
            <?php endif; ?>
            <h2>Ключ доступа</h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline-block;margin-right:10px">
                <input type="hidden" name="action" value="vs_wp_control_generate_token">
                <?php wp_nonce_field('vs_wp_control_generate_token'); ?>
                <?php submit_button(VS_WP_Control_Auth::has_token() ? 'Перевыпустить токен' : 'Создать токен', 'primary', 'submit', false); ?>
            </form>
            <?php if (VS_WP_Control_Auth::has_token()): ?>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline-block">
                    <input type="hidden" name="action" value="vs_wp_control_revoke_token">
                    <?php wp_nonce_field('vs_wp_control_revoke_token'); ?>
                    <?php submit_button('Отозвать токен', 'secondary', 'submit', false); ?>
                </form>
            <?php endif; ?>

            <h2>Разрешения токена</h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="vs_wp_control_save_scopes">
                <?php wp_nonce_field('vs_wp_control_save_scopes'); ?>
                <fieldset>
                    <?php foreach (VS_WP_Control_Auth::all_scopes() as $scope): ?>
                        <label style="display:block;margin:7px 0"><input type="checkbox" name="scopes[]" value="<?php echo esc_attr($scope); ?>" <?php checked(in_array($scope, $scopes, true)); ?>> <code><?php echo esc_html($scope); ?></code></label>
                    <?php endforeach; ?>
                </fieldset>
                <?php submit_button('Сохранить разрешения'); ?>
            </form>

            <h2>Пример запроса</h2>
            <pre style="background:#fff;border:1px solid #ccd0d4;padding:14px;max-width:1000px;overflow:auto">curl -H "Authorization: Bearer YOUR_TOKEN" "<?php echo esc_html($base . '/status'); ?>"</pre>
            <p>Журнал хранит последние 1000 операций API. Страницы, товары и структурные изменения Elementor сохраняются перед изменением для отката.</p>
        </div>
        <?php
    }

    public static function generate_token(): void {
        self::guard('vs_wp_control_generate_token');
        $token = VS_WP_Control_Auth::generate_token();
        set_transient(self::TOKEN_TRANSIENT_PREFIX . get_current_user_id(), $token, 5 * MINUTE_IN_SECONDS);
        self::redirect();
    }

    public static function revoke_token(): void {
        self::guard('vs_wp_control_revoke_token');
        VS_WP_Control_Auth::revoke_token();
        self::redirect();
    }

    public static function save_scopes(): void {
        self::guard('vs_wp_control_save_scopes');
        VS_WP_Control_Auth::set_scopes(isset($_POST['scopes']) ? (array) wp_unslash($_POST['scopes']) : []);
        self::redirect();
    }

    private static function guard(string $action): void {
        if (!current_user_can('manage_options')) {
            wp_die('Forbidden', 'Forbidden', ['response' => 403]);
        }
        check_admin_referer($action);
    }

    private static function redirect(): void {
        wp_safe_redirect(admin_url('tools.php?page=vs-wp-control-api'));
        exit;
    }
}
