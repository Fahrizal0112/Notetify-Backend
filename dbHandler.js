const mysql = require("mysql2/promise");
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
};

const createConnection = async () => {
    try {
      return await mysql.createConnection(dbConfig);
    } catch (error) {
      console.error('Error creating database connection:', error);
      throw error; 
    }
  };
  
  module.exports = createConnection;
  