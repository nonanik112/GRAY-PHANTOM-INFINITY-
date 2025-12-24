-- Create basic tables for Black Phantom Infinity
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    level VARCHAR(10),
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attacks (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50),
    target VARCHAR(255),
    result TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);