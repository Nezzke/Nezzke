<?php
if (!defined('ABSPATH')) { exit; }

final class VS_WP_Control_Plugins {
    private const NS = 'vs-wp-control/v1';
    private const SELF = 'vs-wp-control-api/vs-wp-control-api.php';
    private const MAX_BYTES = 10485760;

    public static function init(): void {
        add_action('rest_api_init', [self::class, 'routes']);
    }

    public static function routes(): void {
        foreach ([
            ['/plugins', WP_REST_Server::READABLE, 'list_route'],
            ['/plugins/install-package', WP_REST_Server::CREATABLE, 'install_route'],
            ['/plugins/activate', WP_REST_Server::CREATABLE, 'activate_route'],
            ['/plugins/deactivate', WP_REST_Server::CREATABLE, 'deactivate_route'],
            ['/plugins/delete', WP_REST_Server::CREATABLE, 'delete_route'],
            ['/self-update/package', WP_REST_Server::CREATABLE, 'self_update_route'],
        ] as [$path,$method,$callback]) {
            register_rest_route(self::NS, $path, [
                'methods' => $method,
                'callback' => [self::class, $callback],
                'permission_callback' => static fn(WP_REST_Request $r) => VS_WP_Control_Auth::permission($r, 'system'),
            ]);
        }
        register_rest_route(self::NS, '/token/status', [
            'methods' => WP_REST_Server::READABLE,
            'callback' => [self::class, 'token_status'],
            'permission_callback' => [self::class, 'admin_permission'],
        ]);
        register_rest_route(self::NS, '/token/configure-hash', [
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'token_configure_hash'],
            'permission_callback' => [self::class, 'admin_permission'],
        ]);
    }

    public static function admin_permission() {
        return is_user_logged_in() && current_user_can('manage_options')
            ? true
            : new WP_Error('vs_admin_required', 'Administrator authentication is required.', ['status'=>403]);
    }

    public static function token_status(): WP_REST_Response {
        return new WP_REST_Response(['ok'=>true,'configured'=>VS_WP_Control_Auth::has_token(),'scopes'=>VS_WP_Control_Auth::get_scopes()], 200);
    }

    public static function token_configure_hash(WP_REST_Request $r) {
        $hash = strtolower(trim((string)$r->get_param('sha256')));
        if (!VS_WP_Control_Auth::set_sha256_hash($hash)) {
            return new WP_Error('vs_token_hash_invalid','sha256 must be a 64-character lowercase hex digest.',['status'=>400]);
        }
        VS_WP_Control_Audit::record('token_configure_hash','system',0,null,['sha256_prefix'=>substr($hash,0,12)],VS_WP_Control_Auth::request_fingerprint($r));
        return new WP_REST_Response(['ok'=>true,'configured'=>true],200);
    }

    public static function list_route(WP_REST_Request $r): WP_REST_Response {
        self::plugin_api();
        $items=[];
        foreach (get_plugins() as $file=>$data) {
            $items[]=['plugin'=>$file,'name'=>(string)($data['Name']??''),'version'=>(string)($data['Version']??''),'active'=>is_plugin_active($file),'protected'=>$file===self::SELF];
        }
        usort($items,static fn($a,$b)=>strcasecmp($a['name'],$b['name']));
        return new WP_REST_Response(['items'=>$items],200);
    }

    public static function install_route(WP_REST_Request $r) {
        if (!self::confirmed($r)) return self::confirm_error();
        $slug=sanitize_key((string)$r->get_param('slug'));
        $main=sanitize_file_name((string)$r->get_param('main_file'));
        $version=sanitize_text_field((string)$r->get_param('version'));
        if (!preg_match('/^[a-z0-9][a-z0-9._-]*$/',$slug) || $main==='' || !str_ends_with(strtolower($main),'.php')) {
            return new WP_Error('vs_package_identity','slug and main_file are required.',['status'=>400]);
        }
        $bytes=self::package_bytes($r); if (is_wp_error($bytes)) return $bytes;
        $sha=self::verify_sha($r,$bytes); if (is_wp_error($sha)) return $sha;
        $res=self::install_bytes($bytes,$slug,$main,$version,rest_sanitize_boolean($r->get_param('replace')),rest_sanitize_boolean($r->get_param('activate')),false);
        if (is_wp_error($res)) return $res;
        VS_WP_Control_Audit::record('plugin_package_install','plugin',0,null,$res+['sha256'=>$sha],VS_WP_Control_Auth::request_fingerprint($r));
        return new WP_REST_Response(['ok'=>true,'sha256'=>$sha]+$res,200);
    }

    public static function self_update_route(WP_REST_Request $r) {
        if (!self::confirmed($r)) return self::confirm_error();
        $version=sanitize_text_field((string)$r->get_param('version'));
        if (!preg_match('/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/',$version)) return new WP_Error('vs_bad_version','Semantic version required.',['status'=>400]);
        if (version_compare($version,VS_WP_CONTROL_VERSION,'<=')) return new WP_Error('vs_not_newer','Requested version must be newer.',['status'=>409]);
        $bytes=self::package_bytes($r); if (is_wp_error($bytes)) return $bytes;
        $sha=self::verify_sha($r,$bytes); if (is_wp_error($sha)) return $sha;
        $res=self::install_bytes($bytes,'vs-wp-control-api','vs-wp-control-api.php',$version,true,false,true);
        if (is_wp_error($res)) return $res;
        VS_WP_Control_Audit::record('self_update','plugin',0,['version'=>VS_WP_CONTROL_VERSION],['version'=>$version,'sha256'=>$sha],VS_WP_Control_Auth::request_fingerprint($r));
        return new WP_REST_Response(['ok'=>true,'from'=>VS_WP_CONTROL_VERSION,'to'=>$version,'sha256'=>$sha,'reload_required'=>true],200);
    }

    public static function activate_route(WP_REST_Request $r) {
        if (!self::confirmed($r)) return self::confirm_error();
        self::plugin_api(); $p=self::plugin($r); if (is_wp_error($p)) return $p;
        if (!is_plugin_active($p)) { $x=activate_plugin($p,'',false,true); if (is_wp_error($x)) return $x; }
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'active'=>true],200);
    }

    public static function deactivate_route(WP_REST_Request $r) {
        if (!self::confirmed($r)) return self::confirm_error();
        self::plugin_api(); $p=self::plugin($r); if (is_wp_error($p)) return $p;
        if ($p===self::SELF) return new WP_Error('vs_plugin_protected','VS WP Control API cannot deactivate itself.',['status'=>409]);
        if (is_plugin_active($p)) deactivate_plugins($p,true,false);
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'active'=>false],200);
    }

    public static function delete_route(WP_REST_Request $r) {
        if (!self::confirmed($r)) return self::confirm_error();
        self::plugin_api(); $p=self::plugin($r); if (is_wp_error($p)) return $p;
        if ($p===self::SELF) return new WP_Error('vs_plugin_protected','VS WP Control API cannot delete itself.',['status'=>409]);
        if (is_plugin_active($p)) return new WP_Error('vs_plugin_active','Deactivate plugin before deleting it.',['status'=>409]);
        $x=delete_plugins([$p]); if (is_wp_error($x)) return $x;
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'deleted'=>true],200);
    }

    private static function install_bytes(string $bytes,string $slug,string $main,string $version,bool $replace,bool $activate,bool $self=false) {
        if (strlen($bytes)>self::MAX_BYTES) return new WP_Error('vs_package_too_large','Package exceeds 10 MiB.',['status'=>413]);
        require_once ABSPATH.'wp-admin/includes/file.php'; self::plugin_api();
        if (!WP_Filesystem()) return new WP_Error('vs_filesystem','WordPress filesystem unavailable.',['status'=>500]);
        global $wp_filesystem;
        $tmp=wp_tempnam($slug.'.zip'); if (!$tmp || file_put_contents($tmp,$bytes)===false) return new WP_Error('vs_temp','Could not write package.',['status'=>500]);
        $check=self::archive_ok($tmp,$slug); if (is_wp_error($check)) { @unlink($tmp); return $check; }
        $base=trailingslashit(WP_CONTENT_DIR).'upgrade/vs-wp-control'; wp_mkdir_p($base);
        $id=gmdate('Ymd-His').'-'.wp_generate_password(6,false,false); $stage=$base.'/stage-'.$id; $backup=$base.'/backup-'.$id; wp_mkdir_p($stage); wp_mkdir_p($backup);
        $unz=unzip_file($tmp,$stage); @unlink($tmp); if (is_wp_error($unz)) return $unz;
        $src=trailingslashit($stage).$slug; $srcmain=trailingslashit($src).$main;
        if (!is_file($srcmain)) return new WP_Error('vs_layout','Package layout invalid.',['status'=>400]);
        $headers=get_plugin_data($srcmain,false,false); if ($version!=='' && (string)($headers['Version']??'')!==$version) return new WP_Error('vs_version_mismatch','Version mismatch.',['status'=>400]);
        $target=trailingslashit(WP_PLUGIN_DIR).$slug; $plugin=$slug.'/'.$main; $exists=is_dir($target);
        if ($exists && !$replace) return new WP_Error('vs_exists','Plugin exists; replace=true required.',['status'=>409]);
        $was_active=$exists && is_plugin_active($plugin);
        if ($exists) { $b=copy_dir($target,trailingslashit($backup).$slug); if (is_wp_error($b)) return $b; }
        $wp_filesystem->delete($target,true); $c=copy_dir($src,$target);
        if (is_wp_error($c) || !is_file(trailingslashit($target).$main)) { self::restore($wp_filesystem,$target,$backup,$slug); return new WP_Error('vs_install_failed','Install failed; backup restored.',['status'=>500]); }
        $verify=get_plugin_data(trailingslashit($target).$main,false,false); if ($version!=='' && (string)($verify['Version']??'')!==$version) { self::restore($wp_filesystem,$target,$backup,$slug); return new WP_Error('vs_verify_failed','Installed version mismatch; backup restored.',['status'=>500]); }
        $wp_filesystem->delete($stage,true);
        if (!$self && ($activate||$was_active) && !is_plugin_active($plugin)) { $a=activate_plugin($plugin,'',false,true); if (is_wp_error($a)) { self::restore($wp_filesystem,$target,$backup,$slug); return $a; } }
        wp_clean_plugins_cache(true); wp_cache_flush();
        return ['plugin'=>$plugin,'version'=>(string)($verify['Version']??''),'active'=>$self?true:is_plugin_active($plugin),'replaced'=>$exists,'backup_id'=>$exists?basename($backup):''];
    }

    private static function archive_ok(string $path,string $slug) {
        if (!class_exists('ZipArchive')) return true;
        $z=new ZipArchive(); if (true!==$z->open($path)) return new WP_Error('vs_zip','Invalid ZIP.',['status'=>400]);
        $total=0; for($i=0;$i<$z->numFiles;$i++){ $s=$z->statIndex($i); $n=str_replace('\\','/',(string)($s['name']??'')); if($n===''||str_starts_with($n,'/')||str_contains($n,'../')||(explode('/',trim($n,'/'))[0]??'')!==$slug){$z->close();return new WP_Error('vs_zip_path','Unsafe ZIP layout.',['status'=>400]);} $total+=(int)($s['size']??0); if($total>52428800){$z->close();return new WP_Error('vs_zip_size','Unpacked package exceeds 50 MiB.',['status'=>413]);}}
        $z->close(); return true;
    }

    private static function package_bytes(WP_REST_Request $r) {
        $b64=preg_replace('/\s+/','',(string)$r->get_param('package_b64')); if($b64==='') return new WP_Error('vs_package_missing','package_b64 is required.',['status'=>400]);
        $bytes=base64_decode($b64,true); return ($bytes===false||$bytes==='')?new WP_Error('vs_package_base64','Invalid base64 package.',['status'=>400]):$bytes;
    }

    private static function verify_sha(WP_REST_Request $r,string $bytes) {
        $expected=strtolower(trim((string)$r->get_param('sha256'))); if(!preg_match('/^[a-f0-9]{64}$/',$expected)) return new WP_Error('vs_sha','Valid SHA-256 required.',['status'=>400]);
        $actual=hash('sha256',$bytes); return hash_equals($expected,$actual)?$actual:new WP_Error('vs_sha_mismatch','SHA-256 mismatch.',['status'=>400]);
    }

    private static function plugin(WP_REST_Request $r) {
        $p=sanitize_text_field((string)$r->get_param('plugin')); if($p===''||str_contains($p,'..')||str_starts_with($p,'/')||!str_ends_with(strtolower($p),'.php')) return new WP_Error('vs_plugin_file','Invalid plugin file.',['status'=>400]);
        return isset(get_plugins()[$p])?$p:new WP_Error('vs_plugin_missing','Plugin not installed.',['status'=>404]);
    }
    private static function confirmed(WP_REST_Request $r): bool { return true===rest_sanitize_boolean($r->get_param('confirm')); }
    private static function confirm_error(): WP_Error { return new WP_Error('vs_confirm','confirm=true is required.',['status'=>400]); }
    private static function plugin_api(): void { require_once ABSPATH.'wp-admin/includes/plugin.php'; }
    private static function restore($fs,string $target,string $backup,string $slug): void { $fs->delete($target,true); $src=trailingslashit($backup).$slug; if(is_dir($src)) copy_dir($src,$target); }
}
