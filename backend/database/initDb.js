const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

async function initDatabase() {
  const host = process.env.DB_HOST || 'localhost';
  const port = parseInt(process.env.DB_PORT || '3306', 10);
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || 'Saha@123';
  const database = process.env.DB_NAME || 'cybercrime_db';

  console.log(`[DB INIT] Connecting to MySQL server at ${host}:${port} as ${user}...`);

  const connection = await mysql.createConnection({
    host,
    port,
    user,
    password,
    multipleStatements: true
  });

  try {
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    await connection.query(`USE \`${database}\`;`);

    // Check existing columns in users table if it exists
    const [userTableCheck] = await connection.query(`SHOW TABLES LIKE 'users';`);
    if (userTableCheck.length > 0) {
      const [columns] = await connection.query(`SHOW COLUMNS FROM users;`);
      const colNames = columns.map(c => c.Field.toLowerCase());

      if (!colNames.includes('password_hash')) {
        console.log('[DB INIT] Adding password_hash column to users table...');
        await connection.query(`ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL AFTER phone;`);
        await connection.query(`UPDATE users SET password_hash = password WHERE password_hash IS NULL AND password IS NOT NULL;`);
      }
      if (!colNames.includes('status')) {
        console.log('[DB INIT] Adding status column to users table...');
        await connection.query(`ALTER TABLE users ADD COLUMN status ENUM('active','inactive','suspended') NOT NULL DEFAULT 'active';`);
      }
      if (!colNames.includes('updated_at')) {
        console.log('[DB INIT] Adding updated_at column to users table...');
        await connection.query(`ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;`);
      }
      if (!colNames.includes('last_login')) {
        console.log('[DB INIT] Adding last_login column to users table...');
        await connection.query(`ALTER TABLE users ADD COLUMN last_login DATETIME DEFAULT NULL;`);
      }
    }

    const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf-8');
    console.log('[DB INIT] Executing schema.sql statements...');
    await connection.query(schemaSql);

    console.log('[DB INIT] Database initialization completed successfully!');
  } catch (error) {
    console.error('[DB INIT] Error during database initialization:', error);
    throw error;
  } finally {
    await connection.end();
  }
}

if (require.main === module) {
  initDatabase().then(() => process.exit(0)).catch(() => process.exit(1));
}

module.exports = { initDatabase };
