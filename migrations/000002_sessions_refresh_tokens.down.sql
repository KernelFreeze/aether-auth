DROP TRIGGER IF EXISTS sessions_archive_on_delete ON sessions;
DROP FUNCTION IF EXISTS archive_deleted_session();
DROP TABLE IF EXISTS archived_sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS session_factors;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS session_user_agents;
