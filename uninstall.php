<?php
/**
 * Uninstall handler for GV Simple Firewall
 * Deletes stored options and prunes firewall logs from uploads.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) exit;

$opt = 'gvfw_settings';

// remove option (single-site or multisite aware)
if (is_multisite()) {
  global $wpdb;
  $blogs = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
  foreach ($blogs as $blog_id) {
    switch_to_blog($blog_id);
    delete_option($opt);
    restore_current_blog();
  }
} else {
  delete_option($opt);
}

// remove logs dir
$uploads = wp_get_upload_dir();
$dir = trailingslashit($uploads['basedir']) . 'gv-firewall';

if (is_dir($dir)) {
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST
  );
  foreach ($it as $file) {
    if ($file->isFile() || $file->isLink()) {
      @unlink($file->getPathname());
    } elseif ($file->isDir()) {
      @rmdir($file->getPathname());
    }
  }
  @rmdir($dir);
}
