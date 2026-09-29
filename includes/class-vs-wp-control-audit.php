<?php
if (!defined('ABSPATH')) {
    exit;
}

final class VS_WP_Control_Audit {
    public static function init(): void {
        $installed = (string) get_option('vs_wp_control_db_version', '');
        if ($installed !== VS_WP_CONTROL_VERSION) {
            self::install();
            update_option('vs_wp_control_db_version', VS_WP_CONTROL_VERSION, false);
        }
    }

    public static function table_name(): string {
        global $wpdb;
        return $wpdb->prefix . 'vs_wp_control_audit';
    }

    public static function install(): void {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = self::table_name();
        $charset = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            actor VARCHAR(100) NOT NULL DEFAULT '',
            action VARCHAR(100) NOT NULL,
            object_type VARCHAR(50) NOT NULL,
            object_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            before_json LONGTEXT NULL,
            after_json LONGTEXT NULL,
            rolled_back_at DATETIME NULL,
            rolled_back_audit_id BIGINT UNSIGNED NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY object_lookup (object_type, object_id),
            KEY created_at (created_at)
        ) {$charset};";
        dbDelta($sql);
    }

    public static function record(string $action, string $object_type, int $object_id, $before, $after, string $actor = ''): int {
        global $wpdb;
        $wpdb->insert(
            self::table_name(),
            [
                'user_id' => get_current_user_id(),
                'actor' => sanitize_text_field($actor),
                'action' => sanitize_key($action),
                'object_type' => sanitize_key($object_type),
                'object_id' => max(0, $object_id),
                'before_json' => null === $before ? null : wp_json_encode($before, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'after_json' => null === $after ? null : wp_json_encode($after, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'created_at' => current_time('mysql', true),
            ],
            ['%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
        );
        $id = (int) $wpdb->insert_id;
        self::prune();
        return $id;
    }

    public static function mark_rolled_back(int $source_id, int $rollback_audit_id): bool {
        global $wpdb;
        return false !== $wpdb->update(
            self::table_name(),
            ['rolled_back_at' => current_time('mysql', true), 'rolled_back_audit_id' => $rollback_audit_id],
            ['id' => $source_id, 'rolled_back_at' => null],
            ['%s', '%d'],
            ['%d', '%s']
        );
    }

    public static function recent(int $limit = 50): array {
        global $wpdb;
        $limit = min(200, max(1, $limit));
        $table = self::table_name();
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id,user_id,actor,action,object_type,object_id,rolled_back_at,rolled_back_audit_id,created_at FROM {$table} ORDER BY id DESC LIMIT %d",
            $limit
        ), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    public static function get(int $id): ?array {
        global $wpdb;
        $table = self::table_name();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id=%d", $id), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function prune(): void {
        global $wpdb;
        $table = self::table_name();
        $wpdb->query("DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT 1000) recent_rows)");
    }
}
