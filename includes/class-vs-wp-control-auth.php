<?php
if (!defined('ABSPATH')) {
    exit;
}

final class VS_WP_Control_Auth {
    private const TOKEN_HASH_OPTION = 'vs_wp_control_token_hash';
    private const TOKEN_SHA256_OPTION = 'vs_wp_control_token_sha256';
    private const SCOPES_OPTION = 'vs_wp_control_scopes';

    public static function all_scopes(): array {
        return ['read', 'content', 'publish', 'media', 'commerce', 'system'];
    }

    public static function get_scopes(): array {
        $scopes = get_option(self::SCOPES_OPTION, []);
        if (!is_array($scopes)) {
            return [];
        }
        return array_values(array_intersect(self::all_scopes(), array_map('sanitize_key', $scopes)));
    }

    public static function set_scopes(array $scopes): void {
        update_option(self::SCOPES_OPTION, array_values(array_intersect(self::all_scopes(), array_map('sanitize_key', $scopes))), false);
    }

    public static function scope_enabled(string $scope): bool {
        return in_array(sanitize_key($scope), self::get_scopes(), true);
    }

    public static function has_token(): bool {
        return (string) get_option(self::TOKEN_SHA256_OPTION, '') !== '' || (string) get_option(self::TOKEN_HASH_OPTION, '') !== '';
    }

    public static function generate_token(): string {
        $raw = rtrim(strtr(base64_encode(random_bytes(36)), '+/', '-_'), '=');
        update_option(self::TOKEN_SHA256_OPTION, hash('sha256', $raw), false);
        update_option(self::TOKEN_HASH_OPTION, self::hash_token($raw), false);
        return $raw;
    }

    public static function set_sha256_hash(string $hash): bool {
        $hash = strtolower(trim($hash));
        if (!preg_match('/^[a-f0-9]{64}$/', $hash)) {
            return false;
        }
        update_option(self::TOKEN_SHA256_OPTION, $hash, false);
        return true;
    }

    public static function revoke_token(): void {
        delete_option(self::TOKEN_SHA256_OPTION);
        delete_option(self::TOKEN_HASH_OPTION);
    }

    public static function permission(WP_REST_Request $request, string $scope = 'read') {
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return true;
        }

        if (!self::has_token()) {
            return new WP_Error('vs_wp_control_token_missing', 'API token has not been configured.', ['status' => 503]);
        }

        if (!in_array($scope, self::get_scopes(), true)) {
            return new WP_Error('vs_wp_control_scope_denied', 'The API token does not have the required scope.', ['status' => 403]);
        }

        $token = self::extract_token($request);
        if ($token === '') {
            return new WP_Error('vs_wp_control_unauthorized', 'Bearer token is required.', ['status' => 401]);
        }

        $expected_sha = (string) get_option(self::TOKEN_SHA256_OPTION, '');
        if ($expected_sha !== '') {
            if (!hash_equals(strtolower($expected_sha), hash('sha256', $token))) {
                return new WP_Error('vs_wp_control_forbidden', 'Invalid API token.', ['status' => 403]);
            }
        } else {
            $expected = (string) get_option(self::TOKEN_HASH_OPTION, '');
            if ($expected === '' || !hash_equals($expected, self::hash_token($token))) {
                return new WP_Error('vs_wp_control_forbidden', 'Invalid API token.', ['status' => 403]);
            }
        }

        return true;
    }

    public static function request_fingerprint(WP_REST_Request $request): string {
        $token = self::extract_token($request);
        if ($token === '') {
            return is_user_logged_in() ? 'wp-user:' . get_current_user_id() : 'anonymous';
        }
        return 'token:' . substr(hash('sha256', $token), 0, 12);
    }

    private static function extract_token(WP_REST_Request $request): string {
        $header = trim((string) $request->get_header('authorization'));
        if (preg_match('/^Bearer\s+(.+)$/i', $header, $m)) {
            return trim($m[1]);
        }
        return trim((string) $request->get_header('x-vs-wp-token'));
    }

    private static function hash_token(string $token): string {
        return hash_hmac('sha256', $token, wp_salt('auth'));
    }
}
