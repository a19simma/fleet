ALTER TABLE user_repos ADD CONSTRAINT user_repos_user_id_id_key UNIQUE (user_id, id);

UPDATE work_project p SET repo_id = NULL
WHERE p.repo_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM user_repos r WHERE r.id = p.repo_id AND r.user_id = p.user_id);

ALTER TABLE work_project DROP CONSTRAINT work_project_repo_id_fkey;

ALTER TABLE work_project ADD CONSTRAINT work_project_repo_owner_fkey
    FOREIGN KEY (user_id, repo_id) REFERENCES user_repos (user_id, id) ON DELETE SET NULL (repo_id);
