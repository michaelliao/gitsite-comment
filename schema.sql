DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    id TEXT NOT NULL PRIMARY KEY,
    role INTEGER NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    locked_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS pages;

CREATE TABLE IF NOT EXISTS pages (
    id TEXT NOT NULL PRIMARY KEY,
    pathname TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS comments;

CREATE TABLE IF NOT EXISTS comments (
    id TEXT NOT NULL PRIMARY KEY,
    page_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_image TEXT NOT NULL,
    content TEXT NOT NULL,
    replies_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS replies;

CREATE TABLE IF NOT EXISTS replies (
    id TEXT NOT NULL PRIMARY KEY,
    comment_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_image TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_c_p_id ON comments(page_id);

CREATE INDEX IF NOT EXISTS idx_r_c_id ON replies(comment_id);
