const {
    register,
    login,
    createNote,
    getNotes,
    getNoteById,
    requestPasswordReset,
    resetPassword,
    updateNote,
    deleteNote
} = require("./Handler");

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
        path: "/notes",
        handler: getNotes,
    },
    {
        method: "GET",
        path: "/note/{noteId}",
        handler: getNoteById,
    },
    {
        method: "POST",
        path: "/request-password-reset",
        handler: requestPasswordReset,
    },
    {
        method: "POST",
        path: "/reset-password",
        handler: resetPassword,
    },
    {
        method: "PUT",
        path: "/note/{noteId}",
        handler: updateNote,
    },
    {
        method: "DELETE",
        path: "/note/{id}",
        handler: deleteNote,
    },
];

module.exports = Routes;
