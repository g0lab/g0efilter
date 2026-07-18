-- Create "api_keys" table
CREATE TABLE `api_keys` (`id` text NOT NULL, `label` text NOT NULL, `key_hash` blob NOT NULL, `key_prefix` text NOT NULL, `created_at` integer NOT NULL, `last_used_at` integer NULL, `revoked_at` integer NULL, PRIMARY KEY (`id`));
-- Create index "api_keys_key_hash_key" to table: "api_keys"
CREATE UNIQUE INDEX `api_keys_key_hash_key` ON `api_keys` (`key_hash`);
-- Create "completed_unblocks" table
CREATE TABLE `completed_unblocks` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `type` text NOT NULL, `value` text NOT NULL, `target_hostname` text NOT NULL DEFAULT (''), `completed_at` integer NOT NULL);
-- Create "fleet_groups" table
CREATE TABLE `fleet_groups` (`id` text NOT NULL, `name` text NOT NULL, `policy` text NOT NULL DEFAULT (''), `filter_mode` text NOT NULL DEFAULT (''), `updated_at` integer NOT NULL, PRIMARY KEY (`id`));
-- Create index "fleet_groups_name_key" to table: "fleet_groups"
CREATE UNIQUE INDEX `fleet_groups_name_key` ON `fleet_groups` (`name`);
-- Create "fleet_instances" table
CREATE TABLE `fleet_instances` (`id` text NOT NULL, `hostname` text NOT NULL, `policy_override` text NULL, `filter_mode` text NOT NULL DEFAULT (''), `reported_version` text NOT NULL DEFAULT (''), `reported_hash` text NOT NULL DEFAULT (''), `last_seen_at` integer NOT NULL, `created_at` integer NOT NULL, `group_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `fleet_instances_fleet_groups_instances` FOREIGN KEY (`group_id`) REFERENCES `fleet_groups` (`id`) ON DELETE SET NULL);
-- Create index "fleet_instances_hostname_key" to table: "fleet_instances"
CREATE UNIQUE INDEX `fleet_instances_hostname_key` ON `fleet_instances` (`hostname`);
-- Create index "instance_group_id" to table: "fleet_instances"
CREATE INDEX `instance_group_id` ON `fleet_instances` (`group_id`);
-- Create "logs" table
CREATE TABLE `logs` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `ts` integer NOT NULL, `data` text NOT NULL, `search` text NOT NULL);
-- Create index "logevent_ts" to table: "logs"
CREATE INDEX `logevent_ts` ON `logs` (`ts`);
-- Create "sessions" table
CREATE TABLE `sessions` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `token_hash` blob NOT NULL, `created_at` integer NOT NULL, `expires_at` integer NOT NULL, `user_id` text NOT NULL, CONSTRAINT `sessions_users_sessions` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "sessions_token_hash_key" to table: "sessions"
CREATE UNIQUE INDEX `sessions_token_hash_key` ON `sessions` (`token_hash`);
-- Create index "session_expires_at" to table: "sessions"
CREATE INDEX `session_expires_at` ON `sessions` (`expires_at`);
-- Create "settings" table
CREATE TABLE `settings` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `key` text NOT NULL, `value` blob NOT NULL);
-- Create index "settings_key_key" to table: "settings"
CREATE UNIQUE INDEX `settings_key_key` ON `settings` (`key`);
-- Create "unblock_requests" table
CREATE TABLE `unblock_requests` (`id` text NOT NULL, `type` text NOT NULL, `value` text NOT NULL, `target_hostname` text NOT NULL DEFAULT (''), `created_at` integer NOT NULL, PRIMARY KEY (`id`));
-- Create index "unblockrequest_type_value_target_hostname" to table: "unblock_requests"
CREATE UNIQUE INDEX `unblockrequest_type_value_target_hostname` ON `unblock_requests` (`type`, `value`, `target_hostname`);
-- Create "users" table
CREATE TABLE `users` (`id` text NOT NULL, `username` text NOT NULL, `password_hash` text NOT NULL, `created_at` integer NOT NULL, PRIMARY KEY (`id`));
-- Create index "users_username_key" to table: "users"
CREATE UNIQUE INDEX `users_username_key` ON `users` (`username`);
