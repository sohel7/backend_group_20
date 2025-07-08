// db.js
const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',         // your MySQL username
    password: '',         // your MySQL password ("" if none)
    database: 'group20_DB'
});

connection.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit();
    }
    console.log('Connected to MySQL database');
});

module.exports = connection;
