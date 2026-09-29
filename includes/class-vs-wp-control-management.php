<?php
if (!defined('ABSPATH')) { exit; }

final class VS_WP_Control_Management {
    private const NS = 'vs-wp-control/v1';
    private const SELF = 'vs-wp-control-api/vs-wp-control-api.php';
    private const MAX_ZIP = 10485760;
    private const MAX_FILES = 1000;
    private const MAX_EXPANDED = 52428800;

    public static function init(): void {
        add_action('rest_api_init', [self::class, 'routes']);
    }

    public static function routes(): void {
        $perm = static fn(WP_REST_Request $r) => VS_WP_Control_Auth::permission($r, 'system');
        register_rest_route(self::NS, '/plugins', [
            'methods' => 'GET', 'callback' => [self::class, 'list_plugins'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/plugins/install-wordpress', [
            'methods' => 'POST', 'callback' => [self::class, 'install_wordpress'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/plugins/install-package', [
            'methods' => 'POST', 'callback' => [self::class, 'install_package'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/plugins/activate', [
            'methods' => 'POST', 'callback' => [self::class, 'activate'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/plugins/deactivate', [
            'methods' => 'POST', 'callback' => [self::class, 'deactivate'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/plugins/delete', [
            'methods' => 'POST', 'callback' => [self::class, 'delete'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/self-update', [
            'methods' => 'POST', 'callback' => [self::class, 'self_update'], 'permission_callback' => $perm,
        ]);
        register_rest_route(self::NS, '/self-update/status', [
            'methods' => 'GET', 'callback' => [self::class, 'update_status'], 'permission_callback' => $perm,
        ]);
    }

    public static function list_plugins(WP_REST_Request $request): WP_REST_Response {
        self::load_plugin_api();
        $plugins = get_plugins();
        $updates = get_site_transient('update_plugins');
        $items = [];
        foreach ($plugins as $file => $data) {
            $items[] = [
                'plugin' => $file,
                'name' => (string)($data['Name'] ?? ''),
                'version' => (string)($data['Version'] ?? ''),
                'active' => is_plugin_active($file),
                'update_available' => isset($updates->response[$file]),
                'update_version' => isset($updates->response[$file]->new_version) ? (string)$updates->response[$file]->new_version : '',
                'protected' => $file === self::SELF,
            ];
        }
        usort($items, static fn($a,$b) => strcasecmp($a['name'],$b['name']));
        return new WP_REST_Response(['items'=>$items], 200);
    }

    public static function install_wordpress(WP_REST_Request $r) {
        if (!self::confirmed($r)) { return self::confirm_error(); }
        $slug = sanitize_key((string)$r->get_param('slug'));
        if ($slug === '' || !preg_match('/^[a-z0-9][a-z0-9._-]*$/', $slug)) {
            return new WP_Error('vs_plugin_bad_slug','Valid WordPress.org slug required.',['status'=>400]);
        }
        self::load_plugin_api();
        require_once ABSPATH.'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH.'wp-admin/includes/plugin-install.php';
        $api = plugins_api('plugin_information',['slug'=>$slug,'fields'=>['sections'=>false]]);
        if (is_wp_error($api) || empty($api->download_link)) {
            return is_wp_error($api) ? $api : new WP_Error('vs_plugin_not_found','Plugin download unavailable.',['status'=>404]);
        }
        $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
        $ok = $upgrader->install($api->download_link,['overwrite_package'=>true]);
        if (is_wp_error($ok)) { return $ok; }
        if (!$ok) { return new WP_Error('vs_plugin_install_failed','Plugin installation failed.',['status'=>500]); }
        $file = (string)$upgrader->plugin_info();
        if ($file === '') { $file = self::find_plugin_by_slug($slug); }
        if ($file === '') { return new WP_Error('vs_plugin_file_missing','Installed plugin main file not resolved.',['status'=>500]); }
        if (rest_sanitize_boolean($r->get_param('activate'))) {
            $a = activate_plugin($file,'',false,true); if (is_wp_error($a)) { return $a; }
        }
        self::audit('plugin_install','plugin',null,['plugin'=>$file,'source'=>'wordpress.org','slug'=>$slug],$r);
        return new WP_REST_Response(['ok'=>true,'plugin'=>$file,'active'=>is_plugin_active($file)],201);
    }

    public static function install_package(WP_REST_Request $r) {
        if (!self::confirmed($r)) { return self::confirm_error(); }
        $slug = sanitize_key((string)$r->get_param('slug'));
        $main = sanitize_file_name((string)$r->get_param('main_file'));
        $version = sanitize_text_field((string)$r->get_param('version'));
        if (!preg_match('/^[a-z0-9][a-z0-9._-]*$/',$slug) || $main==='' || !str_ends_with(strtolower($main),'.php')) {
            return new WP_Error('vs_plugin_identity','slug and main_file are required.',['status'=>400]);
        }
        $bytes = self::decode_package($r); if (is_wp_error($bytes)) { return $bytes; }
        $sha = self::verify_sha($r,$bytes); if (is_wp_error($sha)) { return $sha; }
        $result = self::install_bytes($bytes,$slug,$main,$version,rest_sanitize_boolean($r->get_param('replace')),rest_sanitize_boolean($r->get_param('activate')),false);
        if (is_wp_error($result)) { return $result; }
        self::audit('plugin_package_install','plugin',null,$result+['sha256'=>$sha],$r);
        return new WP_REST_Response(['ok'=>true,'sha256'=>$sha]+$result,201);
    }

    public static function self_update(WP_REST_Request $r) {
        if (!self::confirmed($r)) { return self::confirm_error(); }
        $version = sanitize_text_field((string)$r->get_param('version'));
        if (!preg_match('/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/',$version)) {
            return new WP_Error('vs_update_bad_version','Semantic version required.',['status'=>400]);
        }
        if (version_compare($version,VS_WP_CONTROL_VERSION,'<=')) {
            return new WP_Error('vs_update_not_newer','Requested version must be newer.',['status'=>409]);
        }
        $bytes=self::decode_package($r); if(is_wp_error($bytes)){return $bytes;}
        $sha=self::verify_sha($r,$bytes); if(is_wp_error($sha)){return $sha;}
        $result=self::install_bytes($bytes,'vs-wp-control-api','vs-wp-control-api.php',$version,true,false,true);
        if(is_wp_error($result)){return $result;}
        update_option('vs_wp_control_last_update',['time'=>gmdate('c'),'from'=>VS_WP_CONTROL_VERSION,'to'=>$version,'sha256'=>$sha,'backup'=>$result['backup']??''],false);
        self::audit('self_update','plugin',null,['from'=>VS_WP_CONTROL_VERSION,'to'=>$version,'sha256'=>$sha,'backup'=>$result['backup']??''],$r);
        return new WP_REST_Response(['ok'=>true,'from'=>VS_WP_CONTROL_VERSION,'to'=>$version,'sha256'=>$sha,'backup'=>$result['backup']??''],200);
    }

    public static function update_status(WP_REST_Request $r): WP_REST_Response {
        return new WP_REST_Response([
            'ok'=>true,'version'=>VS_WP_CONTROL_VERSION,'self_update'=>'base64','token_configured'=>VS_WP_Control_Auth::has_token(),
            'last_update'=>get_option('vs_wp_control_last_update',null),
        ],200);
    }

    public static function activate(WP_REST_Request $r) {
        if(!self::confirmed($r)){return self::confirm_error();}
        self::load_plugin_api(); $p=self::plugin_param($r); if(is_wp_error($p)){return $p;}
        $res=activate_plugin($p,'',false,true); if(is_wp_error($res)){return $res;}
        self::audit('plugin_activate','plugin',null,['plugin'=>$p],$r);
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'active'=>true],200);
    }

    public static function deactivate(WP_REST_Request $r) {
        if(!self::confirmed($r)){return self::confirm_error();}
        self::load_plugin_api(); $p=self::plugin_param($r); if(is_wp_error($p)){return $p;}
        if($p===self::SELF){return new WP_Error('vs_plugin_protected','VS WP Control API cannot remotely deactivate itself.',['status'=>409]);}
        deactivate_plugins($p,true,false);
        self::audit('plugin_deactivate','plugin',null,['plugin'=>$p],$r);
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'active'=>false],200);
    }

    public static function delete(WP_REST_Request $r) {
        if(!self::confirmed($r)){return self::confirm_error();}
        self::load_plugin_api(); $p=self::plugin_param($r); if(is_wp_error($p)){return $p;}
        if($p===self::SELF){return new WP_Error('vs_plugin_protected','VS WP Control API cannot remotely delete itself.',['status'=>409]);}
        if(is_plugin_active($p)){return new WP_Error('vs_plugin_active','Deactivate plugin before deletion.',['status'=>409]);}
        $res=delete_plugins([$p]); if(is_wp_error($res)){return $res;}
        self::audit('plugin_delete','plugin',['plugin'=>$p],null,$r);
        return new WP_REST_Response(['ok'=>true,'plugin'=>$p,'deleted'=>true],200);
    }

    private static function install_bytes(string $bytes,string $slug,string $main,string $expected,bool $replace,bool $activate,bool $self=false) {
        if(strlen($bytes)>self::MAX_ZIP){return new WP_Error('vs_package_too_large','Package exceeds 10 MiB.',['status'=>413]);}
        require_once ABSPATH.'wp-admin/includes/file.php';
        $tmp=wp_tempnam('vs-wp-control.zip'); if(!$tmp||file_put_contents($tmp,$bytes)===false){return new WP_Error('vs_package_temp','Could not write temp package.',['status'=>500]);}
        $stage=trailingslashit(WP_CONTENT_DIR).'upgrade/vs-wp-'.wp_generate_uuid4(); wp_mkdir_p($stage);
        $unz=unzip_file($tmp,$stage); @unlink($tmp); if(is_wp_error($unz)){self::rm($stage);return $unz;}
        $root=self::payload_root($stage,$slug); if(is_wp_error($root)){self::rm($stage);return $root;}
        $scan=self::scan_tree($root); if(is_wp_error($scan)){self::rm($stage);return $scan;}
        $mainPath=$root.'/'.$main; if(!is_file($mainPath)){self::rm($stage);return new WP_Error('vs_package_main_missing','Main plugin file missing.',['status'=>400]);}
        $data=get_file_data($mainPath,['Version'=>'Version'],'plugin'); $actual=(string)($data['Version']??'');
        if($expected!==''&&$actual!==$expected){self::rm($stage);return new WP_Error('vs_package_version','Package version mismatch.',['status'=>400]);}
        $dest=trailingslashit(WP_PLUGIN_DIR).$slug; $backup='';
        if(is_dir($dest)){
            if(!$replace){self::rm($stage);return new WP_Error('vs_plugin_exists','Plugin already exists; set replace=true.',['status'=>409]);}
            $backup=trailingslashit(WP_CONTENT_DIR).'vs-wp-control-backups/'.gmdate('Ymd-His').'-'.sanitize_file_name($slug); wp_mkdir_p(dirname($backup));
            if(!self::cp($dest,$backup)){self::rm($stage);return new WP_Error('vs_backup_failed','Could not create backup.',['status'=>500]);}
        }
        $wasActive=self::is_active_file($slug.'/'.$main);
        self::rm($dest); wp_mkdir_p($dest);
        if(!self::cp($root,$dest)){
            self::rm($dest); if($backup&&is_dir($backup)){self::cp($backup,$dest);} self::rm($stage);
            return new WP_Error('vs_install_failed','Install failed; previous version restored.',['status'=>500]);
        }
        self::rm($stage); if(function_exists('opcache_reset')){@opcache_reset();}
        self::load_plugin_api();
        if($activate||($self&&$wasActive)){
            $file=$slug.'/'.$main; if(!is_plugin_active($file)){ $a=activate_plugin($file,'',false,true); if(is_wp_error($a)){return $a;} }
        }
        return ['plugin'=>$slug.'/'.$main,'version'=>$actual,'active'=>is_plugin_active($slug.'/'.$main),'backup'=>$backup?basename($backup):''];
    }

    private static function decode_package(WP_REST_Request $r) {
        $b64=preg_replace('/\s+/','',(string)$r->get_param('package_b64'));
        if($b64===''){return new WP_Error('vs_package_missing','package_b64 is required.',['status'=>400]);}
        $bytes=base64_decode($b64,true); if($bytes===false||$bytes===''){return new WP_Error('vs_package_base64','Invalid base64 package.',['status'=>400]);}
        return $bytes;
    }
    private static function verify_sha(WP_REST_Request $r,string $bytes) {
        $want=strtolower(trim((string)$r->get_param('sha256'))); if(!preg_match('/^[a-f0-9]{64}$/',$want)){return new WP_Error('vs_package_hash','Valid sha256 required.',['status'=>400]);}
        $got=hash('sha256',$bytes); if(!hash_equals($want,$got)){return new WP_Error('vs_package_hash_mismatch','SHA-256 mismatch.',['status'=>400]);} return $got;
    }
    private static function payload_root(string $stage,string $slug) {
        if(is_file($stage.'/vs-wp-control-api.php')||is_file($stage.'/'.$slug.'.php')){return $stage;}
        $dirs=glob($stage.'/*',GLOB_ONLYDIR)?:[]; if(count($dirs)!==1){return new WP_Error('vs_package_layout','Package must contain one plugin root.',['status'=>400]);} return $dirs[0];
    }
    private static function scan_tree(string $root) {
        $count=0;$bytes=0;$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS));
        foreach($it as $f){$count++; if($count>self::MAX_FILES){return new WP_Error('vs_package_files','Too many files.',['status'=>413]);} if($f->isLink()){return new WP_Error('vs_package_symlink','Symlinks are not allowed.',['status'=>400]);} $bytes+=$f->getSize(); if($bytes>self::MAX_EXPANDED){return new WP_Error('vs_package_expanded','Expanded package too large.',['status'=>413]);}}
        return true;
    }
    private static function plugin_param(WP_REST_Request $r){$p=sanitize_text_field((string)$r->get_param('plugin'));self::load_plugin_api();$all=get_plugins();return isset($all[$p])?$p:new WP_Error('vs_plugin_missing','Plugin not found.',['status'=>404]);}
    private static function find_plugin_by_slug(string $slug): string {self::load_plugin_api();foreach(get_plugins() as $f=>$d){if(str_starts_with($f,$slug.'/')){return $f;}}return '';}
    private static function load_plugin_api(): void {require_once ABSPATH.'wp-admin/includes/plugin.php'; require_once ABSPATH.'wp-admin/includes/file.php';}
    private static function confirmed(WP_REST_Request $r): bool {return rest_sanitize_boolean($r->get_param('confirm'));}
    private static function confirm_error(): WP_Error {return new WP_Error('vs_confirm_required','Set confirm=true for this system operation.',['status'=>400]);}
    private static function is_active_file(string $f): bool {self::load_plugin_api();return is_plugin_active($f);}
    private static function audit(string $action,string $type,$before,$after,WP_REST_Request $r): void {if(class_exists('VS_WP_Control_Audit')){VS_WP_Control_Audit::record($action,$type,0,$before,$after,VS_WP_Control_Auth::request_fingerprint($r));}}
    private static function cp(string $src,string $dst): bool {if(!is_dir($src)){return false;}if(!is_dir($dst)&&!wp_mkdir_p($dst)){return false;}foreach(scandir($src)?:[] as $n){if($n==='.'||$n==='..'){continue;}$a=$src.'/'.$n;$b=$dst.'/'.$n;if(is_dir($a)){if(!self::cp($a,$b)){return false;}}elseif(!copy($a,$b)){return false;}}return true;}
    private static function rm(string $dir): void {if(!is_dir($dir)){return;}foreach(scandir($dir)?:[] as $n){if($n==='.'||$n==='..'){continue;}$p=$dir.'/'.$n;if(is_dir($p)){self::rm($p);}else{@unlink($p);}}@rmdir($dir);}
}
