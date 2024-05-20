const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const createConnection = require('./dbHandler');
require('dotenv').config();

const register = async (request, h) => {
    const { username, email, password } = request.payload;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT email FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            return h.response({ message: 'Email already registered' }).code(400);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, new Date()]
        );

        return h.response({ message: 'User registered successfully', user_id: result.insertId }).code(201);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

const login = async (request, h) => {
    const { email, password } = request.payload;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return h.response({ message: 'Invalid email or password' }).code(401);
        }

        const user = rows[0];

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return h.response({ message: 'Invalid email or password' }).code(401);
        }

        // Buat token JWT
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return h.response({ message:'Berhasil Login! Selamat Datang',user,token }).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

const createNote = async (request, h) => {
    const token = request.headers.authorization;
    if (!token) {
        return h.response({ message: 'Unauthorized' }).code(401);
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;
        const { title, content } = request.payload;

        const connection = await createConnection();

        const [result] = await connection.execute(
            'INSERT INTO notes (user_id, title, content, created_at) VALUES (?, ?, ?, ?)',
            [userId, title, content, new Date()]
        );

        return h.response({ message: 'Note created successfully', note_id: result.insertId }).code(201);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    }
};


const getNotes = async (request, h) => {
    const token = request.headers.authorization;
    if (!token) {
        return h.response({ message: 'Unauthorized' }).code(401);
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;

        const connection = await createConnection();
        const [rows] = await connection.execute('SELECT * FROM notes WHERE user_id = ?', [userId]);
        connection.end();

        return h.response(rows).code(200);
    } catch (error) {
        console.error(error);
        return h.response({ message: 'Unauthorized' }).code(401);
    }
};

const getNoteById = async (request, h) => {
    const token = request.headers.authorization;
    if (!token) {
        return h.response({ message: 'Unauthorized' }).code(401);
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;

        const noteId = request.params.noteId;
        const connection = await createConnection();
        const [rows] = await connection.execute('SELECT * FROM notes WHERE id = ? AND user_id = ?', [noteId, userId]);
        connection.end();

        if (rows.length === 0) {
            return h.response({ message: 'Note not found' }).code(404);
        }

        return h.response(rows[0]).code(200);
    } catch (error) {
        console.error(error);
        return h.response({ message: 'Unauthorized' }).code(401);
    }
};

module.exports = {
    register,
    login,
    createNote,
    getNotes,
    getNoteById,
};
