-- create the database if it doesnt exist
CREATE DATABASE IF NOT EXISTS proxy;

-- use the proxy database
USE proxy;

-- create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(64) NOT NULL,
    thread_limit INT NOT NULL DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL DEFAULT NULL
);

-- Create admins table
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_key VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- for the love of god change this api key
INSERT INTO admins (api_key)
SELECT 'gov6apikey'
FROM dual
WHERE NOT EXISTS (SELECT 1 FROM admins LIMIT 1);

-- insert default user if not exists
INSERT INTO users (username, password, thread_limit, expires_at)
SELECT 'admin', 'make sure im sha256!', 100, NULL
FROM dual
WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1); 