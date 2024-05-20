const { register, login, createNote, getNotes, getNoteById } = require("./Handler");

const Routes = [
    {
        method: "POST",
        path: "/register",
        handler: register,
    },
    {
        method: "POST",
        path: "/login",
        handler: login,
    },
    {
        method: "POST",
        path: "/note",
        handler: createNote,
    },
    {
        method: "GET",
        path: "/note",
        handler: getNotes,
    },
    {
        method: "GET",
        path: "/note/{noteId}",
        handler: getNoteById,
    }
];

module.exports = Routes;
