const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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
    const { noteId } = request.params;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT * FROM notes WHERE id = ?', [noteId]);
        if (rows.length === 0) {
            return h.response({ message: 'Note not found' }).code(404);
        }

        return h.response(rows[0]).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

const updateNote = async (request, h) => {
    const { noteId } = request.params;
    const { title, content } = request.payload;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT * FROM notes WHERE id = ?', [noteId]);
        if (rows.length === 0) {
            return h.response({ message: 'Note not found or you do not have permission to update this note' }).code(404);
        }

        await connection.execute(
            'UPDATE notes SET title = ?, content = ? WHERE id = ?',
            [title, content, noteId]
        );

        return h.response({ message: 'Note updated successfully' }).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};


const deleteNote = async (request, h) => {
    const { id } = request.params;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT * FROM notes WHERE id = ?', [id]);
        if (rows.length === 0) {
            return h.response({ message: 'Note not found or you do not have permission to delete this note' }).code(404);
        }

        await connection.execute('DELETE FROM notes WHERE id = ?', [id]);

        return h.response({ message: 'Note deleted successfully' }).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

const requestPasswordReset = async (request, h) => {
    const { email } = request.payload;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return h.response({ message: 'Email not found' }).code(404);
        }

        const userId = rows[0].id;
        const token = crypto.randomBytes(20).toString('hex');
        const expires = new Date(Date.now() + 3600000); 

        await connection.execute(
            'INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)',
            [userId, token, expires]
        );

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            secure:true,
            logger:true,
            debug:true,
            secureConnection:false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
            tls:{
                rejectUnauthorized:true
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account. Please Copy an paste this into our application to complete the process:
                   \n${token}\n
                   If you did not request this, please ignore this email and your password will remain unchanged.`,
        };

        await transporter.sendMail(mailOptions);

        return h.response({ message: 'Password reset email sent' }).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

const createReminder = async (request, h) => {
    const { noteId, title, content, reminderDate } = request.payload;
    const token = request.headers.authorization;

    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;

        const connection = await createConnection();

        try {
            let noteIdToUse = noteId;

            if (!noteId) {
                const [result] = await connection.execute(
                    'INSERT INTO notes (user_id, title, content, created_at) VALUES (?, ?, ?, ?)',
                    [userId, title, content, new Date()]
                );

                noteIdToUse = result.insertId;
            } else {
                const [noteRows] = await connection.execute('SELECT * FROM notes WHERE id = ? AND user_id = ?', [noteId, userId]);
                if (noteRows.length === 0) {
                    return h.response({ message: 'Note not found or you do not have permission' }).code(404);
                }
            }

            const [reminderResult] = await connection.execute(
                'INSERT INTO reminders (note_id, title, reminder_date, created_at) VALUES (?, ?, ?, ?)',
                [noteIdToUse, title, reminderDate, new Date()]
            );

            return h.response({ message: 'Reminder created successfully', reminder_id: reminderResult.insertId }).code(201);
        } catch (err) {
            console.error(err);
            return h.response({ message: 'Internal Server Error' }).code(500);
        } finally {
            connection.end();
        }
    } catch (error) {
        console.error(error);
        return h.response({ message: 'Unauthorized' }).code(401);
    }
};

const getReminderById = async (request, h) => {
    const token = request.header.authorization;

    try{
        const decoded = jwt.verify(token.split(' ')[1],process.env.JWT_SECRET);
        const userId = decoded.id;
        const {id} = request.params;

        const connection = await createConnection();

        try {
            const [rows] = await connection.execute(
               `SELECT r.* FROM reminders r JOIN notes n ON r.note_id = n.id WHERE r.id = ? AND n.user_id = ?`,
                [id, userId]
            );
            if (rows.length === 0 ){
                return h.response({ message: 'Reminder not found'}),code(404);
            }
            return h.response(rows[0]).code(200);
        } catch (err) {
            return h.response({ message: 'Internal Server Error'}).code(500);
        } finally {
            connection.end();
        }
    } catch (error) {
        console.error(error);
        return h.response({message : 'Unauthorized'}).code(401);
    }
};

const updateReminder = async (request, h) => {
    const token = request.headers.authorization;

    // Verifikasi token JWT
    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;
        const { id } = request.params;
        const { title, reminderDate } = request.payload;

        const connection = await createConnection();

        try {
            // Periksa apakah reminder dengan id tertentu ada dan milik user
            const [rows] = await connection.execute(
                `SELECT r.* FROM reminders r JOIN notes n ON r.note_id = n.id WHERE r.id = ? AND n.user_id = ?`,
                [id, userId]
            );
            if (rows.length === 0) {
                return h.response({ message: 'Reminder not found or you do not have permission' }).code(404);
            }

            // Update reminder
            await connection.execute(
                'UPDATE reminders SET title = ?, reminder_date = ? WHERE id = ?',
                [title, reminderDate, id]
            );

            return h.response({ message: 'Reminder updated successfully' }).code(200);
        } catch (err) {
            console.error(err);
            return h.response({ message: 'Internal Server Error' }).code(500);
        } finally {
            connection.end();
        }
    } catch (error) {
        console.error(error);
        return h.response({ message: 'Unauthorized' }).code(401);
    }
};

const deleteReminder = async (request, h) => {
    const token = request.headers.authorization;

    // Verifikasi token JWT
    try {
        const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
        const userId = decoded.id;
        const { id } = request.params;

        const connection = await createConnection();

        try {
            // Periksa apakah reminder dengan id tertentu ada dan milik user
            const [rows] = await connection.execute(
                `SELECT r.* FROM reminders r JOIN notes n ON r.note_id = n.id WHERE r.id = ? AND n.user_id = ?`,
                [id, userId]
            );
            if (rows.length === 0) {
                return h.response({ message: 'Reminder not found or you do not have permission' }).code(404);
            }

            // Hapus reminder
            await connection.execute('DELETE FROM reminders WHERE id = ?', [id]);

            return h.response({ message: 'Reminder deleted successfully' }).code(200);
        } catch (err) {
            console.error(err);
            return h.response({ message: 'Internal Server Error' }).code(500);
        } finally {
            connection.end();
        }
    } catch (error) {
        console.error(error);
        return h.response({ message: 'Unauthorized' }).code(401);
    }
};

const resetPassword = async (request, h) => {
    const { token, newPassword } = request.payload;
    const connection = await createConnection();

    try {
        const [rows] = await connection.execute('SELECT user_id, expires FROM password_resets WHERE token = ?', [token]);
        if (rows.length === 0) {
            return h.response({ message: 'Invalid or expired token' }).code(400);
        }

        const resetRequest = rows[0];

        if (new Date() > resetRequest.expires) {
            return h.response({ message: 'Token expired' }).code(400);
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await connection.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, resetRequest.user_id]
        );

        await connection.execute(
            'DELETE FROM password_resets WHERE token = ?',
            [token]
        );

        return h.response({ message: 'Password reset successfully' }).code(200);
    } catch (err) {
        console.error(err);
        return h.response({ message: 'Internal Server Error' }).code(500);
    } finally {
        connection.end();
    }
};

module.exports = {
    register,
    login,
    createNote,
    getNotes,
    getNoteById,
    requestPasswordReset,
    resetPassword,
    updateNote,
    deleteNote,
    createReminder,
    getReminderById,
    updateReminder,
    deleteReminder
};
